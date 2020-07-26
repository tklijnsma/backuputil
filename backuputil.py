# -*- coding: utf-8 -*-
import os.path as osp
import logging, subprocess, os, glob, shutil, datetime

DEFAULT_LOGGING_LEVEL = logging.INFO

def setup_logger(name='backuputil'):
    if name in logging.Logger.manager.loggerDict:
        logger = logging.getLogger(name)
        logger.info('Logger %s is already defined', name)
    else:
        fmt = logging.Formatter(
            fmt = (
                '\033[33m%(levelname)7s:%(asctime)s:%(module)s:%(lineno)s\033[0m'
                + ' %(message)s'
                ),
            datefmt='%Y-%m-%d %H:%M:%S'
            )
        handler = logging.StreamHandler()
        handler.setFormatter(fmt)
        logger = logging.getLogger(name)
        logger.setLevel(DEFAULT_LOGGING_LEVEL)
        logger.addHandler(handler)
    return logger
logger = setup_logger()

def set_logfile(path='log_%t.log'):
    path = path.replace('%t', _timestamp_now())
    handler = logging.FileHandler(path)
    handler.setFormatter(logging.Formatter(
        fmt = (
            '%(asctime)s:%(levelname)7s: %(message)s'
            + ''
            ),
        datefmt='%Y-%m-%d %H:%M:%S'
        ))
    logger.addHandler(handler)
    return handler # In case one wants to remove it later

from contextlib import contextmanager
@contextmanager
def logfile(logfilepath):
    """
    Context manager to set a logfile temporarily.
    """
    handler = set_logfile(logfilepath)
    try:
        yield handler
    finally:
        # Delete the handler from the logger again
        logger.handlers = [ h for h in logger.handlers if not(h is handler) ]

def debug(flag=True):
    """Sets the logger level to debug (for True) or warning (for False)"""
    logger.setLevel(logging.DEBUG if flag else DEFAULT_LOGGING_LEVEL)

DRYMODE = False
def drymode(flag=True):
    global DRYMODE
    DRYMODE = flag
    # This is pretty hacky:
    if flag:
        logger.handlers[0].formatter._style._fmt = logger.handlers[0].formatter._style._fmt.replace('%(levelname)', '(dry) %(levelname)')
    else:
        logger.handlers[0].formatter._style._fmt = logger.handlers[0].formatter._style._fmt.replace('(dry) ', '')

def is_string(string):
    """
    Checks strictly whether `string` is a string
    Python 2/3 compatibility (https://stackoverflow.com/a/22679982/9209944)
    """
    try:
        basestring
    except NameError:
        basestring = str
    return isinstance(string, basestring)

def run_command(cmd, non_zero_exitcode_ok=False, shell=False, dry=None, log_fn=None):
    """
    Runs a command and captures output. Raises an exception on non-zero exit code,
    except if non_zero_exitcode_ok is set to True.

    If dry is True, the command is just printed.
    If dry is None, dry is inherited from the global dry state
    """
    if dry is None: dry = DRYMODE
    logger.info('Issuing command: %s', ' '.join(cmd) if not(is_string(cmd)) else cmd)
    if dry: return 'dry output'
    if shell and not is_string(cmd): cmd = ' '.join(cmd)
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        shell=shell
        )
    # Start running command and capturing output
    output = []
    for stdout_line in iter(process.stdout.readline, ''):
        if log_fn is None:
            logger.debug('CMD: ' + stdout_line.strip('\n'))
        else:
            log_fn('CMD: ' + stdout_line.strip('\n'))
        output.append(stdout_line)
    process.stdout.close()
    process.wait()
    returncode = process.returncode
    # Return output only if command succeeded
    if returncode == 0:
        logger.info('Command exited with status 0 - all good')
    else:
        if non_zero_exitcode_ok:
            logger.info('Command exited with status %s', return_code)
            return returncode
        else:
            logger.error('Exit status {0} for command: {1}'.format(returncode, cmd))
            logger.error('Output:\n%s', '\n'.join(output))
            raise subprocess.CalledProcessError(cmd, returncode)
    return output

def get_exitcode(cmd, dry=None):
    """
    Runs a command and returns the exit code.
    """
    if dry is None: dry = DRYMODE
    if is_string(cmd): cmd = [cmd]
    logger.debug('Getting exit code for "%s"', ' '.join(cmd))
    if dry: return 0
    FNULL = open(os.devnull, 'w')
    process = subprocess.Popen(cmd, stdout=FNULL, stderr=subprocess.STDOUT)
    process.communicate()[0]
    logger.debug('Got exit code %s', process.returncode)
    return process.returncode

def bytes_to_human_readable(num, suffix='B'):
    """
    Convert number of bytes to a human readable string
    """
    for unit in ['','k','M','G','T','P','E','Z']:
        if abs(num) < 1024.0:
            return '{0:3.1f} {1}b'.format(num, unit)
        num /= 1024.0
    return '{0:3.1f} {1}b'.format(num, 'Y')

# ___________________________________________
# Path management

def has_machine(path):
    return ':' in path

def _split(path):
    machine, path = path.split(':',1)
    return machine, path

def _join(machine, path):
    return machine + ':' + path

def format(path, machine=None):
    if has_machine(path):
        machine_from_path, local_path = _split(path)
        if not(machine is None) and machine_from_path != machine:
            raise ValueError(
                'Machine from path {0} does not match given machine {1}'
                .format(machine_from_path, machine)
                )
        return _join(machine, local_path)
    else:
        if machine is None:
            raise ValueError(
                'Machine not specified'
                )
        return _join(machine, path)

# ___________________________________________
# Interactions

class Inode(object):

    SHALLOW_COMPARE = True

    @classmethod
    def from_lsline(cls, line, machine=None):
        import datetime
        components = line.strip().split()
        path = components[8]
        isdir = components[0].startswith('d')
        size = int(components[4])
        timestamp = ' '.join(components[5:8])
        try:
            modtime = datetime.datetime.strptime(timestamp, '%b %d %H:%M')
        except ValueError:
            try:
                modtime = datetime.datetime.strptime(timestamp, '%b %d %Y')
            except:
                logger.error(
                    'Tried multiple date formats, but this line has no modtime:\n%s',
                    line
                    )
                raise
        return cls(path, size, isdir, modtime, machine)

    @classmethod
    def from_findline(cls, line, machine=None):
        import datetime
        components = line.strip().split()
        path = components[-1]
        isdir = components[0] == 'd'
        size = int(components[1])
        modtime = datetime.datetime.fromtimestamp(float(components[2]))
        return cls(path, size, isdir, modtime, machine)

    def __init__(self, path, size, isdir, modtime, machine=None):
        self.local_path = path
        self.path = _join(machine, path) if machine else path
        self.size = size
        self.isdir = isdir
        self.isfile = ~isdir
        self.modtime = modtime
        self.size_human = bytes_to_human_readable(self.size)

    def __repr__(self):
        return '<Inode {isdir} {size} {modtime} {path}>'.format(
            isdir = 'd' if self.isdir else 'f',
            size = self.size,
            modtime = self.modtime.strftime('%b%d'),
            path = self.path
            )

    def __eq__(self, other):
        return all([
            self.path == other.path,
            self.isdir == other.isdir,
            abs(1. - (float(self.size) / other.size if other.size != 0. else 1.)) < 0.1,
            ])

    def __hash__(self):
        return hash(self.path + ' ' + str(self.isdir))

    def set_basepath(self, basepath):
        """
        Temporarily sets self.path to a relative path w.r.t. basepath.
        This allows one to compare inodes that are on different machines.
        """
        self._fullpath = self.path
        self.path = osp.relpath(self.path, basepath)

    def unset_basepath(self):
        """
        Undoes set_basepath
        """
        if hasattr(self, '_fullpath'):
            self.path = self._fullpath

def _get_find_cmd(path, stat=False, recursive=True):
    find_cmd = 'find {0}'.format(path)
    if stat:
        find_cmd += ' -printf \'%y %s %A@ %p\n\''
    if not recursive:
        find_cmd += ' -maxdepth 1'
    return find_cmd

def compile_ssh(**ssh_args):
    """
    Looks through options in the ssh_args dict and builds a command line
    for ssh
    """
    cmd = ['ssh']
    if 'port' in ssh_args:
        cmd.append('-p')
        cmd.append(str(ssh_args['port']))
    return cmd

def _get_ssh_cmd(machine, command_to_run, **ssh_args):
    """
    Compiles ssh options, and puts the machine and command_to_run in the right place
    """
    return compile_ssh(**ssh_args) + [ machine, '"' + command_to_run + '"' ]
    
def _find_lines_to_inodes(lines, machine=None):
    inodes = []
    for line in lines:
        line = line.strip()
        if len(line) == 0: continue
        try:
            inodes.append(Inode.from_findline(line, machine))
        except ValueError:
            logger.error('Could not make inode, skipping line: %s', line)
    return inodes

def _listdir_find_remote(path, stat=False, recursive=True, **ssh_args):
    machine, local_path = _split(path)
    cmd = _get_ssh_cmd(machine, _get_find_cmd(local_path, stat, recursive), **ssh_args)
    contents = run_command(cmd, shell=True, dry=False)
    return _find_lines_to_inodes(contents, machine) if stat else [ _join(machine, i) for i in contents ]

def _listdir_find_local(path, stat=False, recursive=True):
    """
    Find is probably still faster than using os.walk, even for local
    """
    contents = run_command(_get_find_cmd(path, stat, recursive), shell=True, dry=False)
    return _find_lines_to_inodes(contents) if stat else contents

def _ls_lines_to_inodes(lines, machine):
    inodes = []
    for line in lines:
        line = line.strip()
        if len(line) == 0 or line.startswith('total:'):
            continue
        inodes.append(Inode.from_lsline(line, machine))
    return inodes

def _listdir_ls_remote(path, stat=False, **ssh_args):
    machine, local_path = _split(path)
    cmd = _get_ssh_cmd(machine, 'ls -ld {0}/*'.format(local_path), **ssh_args)
    contents = run_command(cmd, shell=True, dry=False)
    inodes = _ls_lines_to_inodes(contents, machine)
    return inodes if stat else [ i.path for i in inodes ]

def _listdir_ls_local(path, stat=False, **ssh_args):
    cmd = 'ls -ld {0}/*'.format(path)
    contents = run_command(cmd, shell=True, dry=False)
    return _ls_lines_to_inodes(contents) if stat else [ i.path for i in _ls_lines_to_inodes(contents) ]

def listdir(path, *args, **kwargs):
    recursive = kwargs.get('recursive', True)
    if has_machine(path):
        if recursive:
            return _listdir_find_remote(path, *args, **kwargs)
        else:
            return _listdir_ls_remote(path, *args, **kwargs)
    else:
        if recursive:
            return _listdir_find_local(path, *args, **kwargs)
        else:
            return _listdir_ls_local(path, *args, **kwargs)

def _rmtree_remote(path, **ssh_args):
    machine, local_path = _split(path)
    # Do some validation since 'rm -rf' is pretty dangerous
    if not local_path.startswith('/'):
        raise ValueError('{0}: not an absolute path'.format(local_path))
    elif local_path.count('/') <= 2:
        raise ValueError('{0}: this is a very low level path, is it a mistake?'.format(local_path))
    cmd = _get_ssh_cmd(machine, 'rm -rf {0}'.format(local_path), **ssh_args)
    run_command(cmd, shell=True)

def rmtree(path, **ssh_args):
    logger.info('Deleting %s', path)
    if has_machine(path):
        _rmtree_remote(path, **ssh_args)
    else:
        if not DRYMODE:
            # shutil.rmtree(path)
            print('DOING shutil.rmtree({0})'.format(path))

# ___________________________________________
# Utilities using interactions

def _compare_paths(paths_a, paths_b, base_path_a=None, base_path_b=None):
    if base_path_a: paths_a = [ osp.relpath(p, base_path_a) for p in paths_a ]
    if base_path_b: paths_b = [ osp.relpath(p, base_path_b) for p in paths_b ]
    set_a = set(paths_a)
    set_b = set(paths_b)
    intersection = set_a.intersection(set_b)
    only_a = set_a - set_b
    only_b = set_b - set_a
    return intersection, only_a, only_b

def _compare_inodes(inodes_a, inodes_b, base_path_a=None, base_path_b=None):
    """
    Compares two lists of inodes
    Returns intersection, only_a, only_b
    """
    try:
        if base_path_a: [i.set_basepath(base_path_a) for i in inodes_a]
        if base_path_b: [i.set_basepath(base_path_b) for i in inodes_b]
        set_a = set(inodes_a)
        set_b = set(inodes_b)
        intersection = set_a.intersection(set_b)
        only_a = set_a - set_b
        only_b = set_b - set_a
        return intersection, only_a, only_b
    finally:
        if base_path_a: [i.unset_basepath() for i in inodes_a]
        if base_path_b: [i.unset_basepath() for i in inodes_b]

def compare(inodes_a, inodes_b, base_path_a=None, base_path_b=None):
    if len(inodes_a) == 0 and len(inodes_b) == 0:
        return set(), set(), set()
    example_inode = inodes_a[0] if len(inodes_a) else inodes_b[0]
    if isinstance(example_inode, Inode):
        return _compare_inodes(inodes_a, inodes_b, base_path_a=None, base_path_b=None)
    else:
        return _compare_paths(inodes_a, inodes_b, base_path_a=None, base_path_b=None)


# ___________________________________________
# Backup interactions

TIMESTAMP_FMT = '%Y-%m-%d_%H%M'

def _timestamp_now():
    return datetime.datetime.now().strftime(TIMESTAMP_FMT)

def _get_snapshotsdir(backupdir):
    """
    Default snapshot directory for a directory to be backed up
    """
    return osp.join(
        osp.dirname(backupdir),
        'snapshots_' + osp.basename(backupdir)
        )

def make_snapshot(backupdir, **ssh_args):
    """
    Takes a directory, and puts a copy with hardlinks (so no file duplication)
    in <directory>/../snaphots/<directory>_<snapshottime>.
    """
    snapshotdir = osp.join(_get_snapshotsdir(backupdir), _timestamp_now())
    if not(has_machine(backupdir)) and osp.isdir(snapshotdir):
        # TODO: Checking dir existence over ssh
        raise RuntimeError(
            'Target snapshot directory {0} already exists'
            .format(snapshotdir)
            )
    logger.info('Creating snapshot %s --> %s', osp.basename(backupdir), snapshotdir)
    if has_machine(backupdir):
        machine, src = _split(backupdir)
        _, dst = _split(snapshotdir)
        cp_cmd = 'cp -al {0} {1}'.format(src, dst) # TODO: cp -l is not posix, and does not exist on OSX
        cmd = _get_ssh_cmd(machine, cp_cmd, **ssh_args)
        output = run_command(cmd, shell=True)
        logger.debug(output)
    else:
        if not DRYMODE: shutil.copytree(backupdir, snapshotdir, copy_function=os.link)

def list_snapshots(backupdir, **ssh_args):
    snapshots = listdir(_get_snapshotsdir(backupdir), recursive=False, stat=True, **ssh_args)
    for s in snapshots:
        s.snapshot_time = datetime.datetime.strptime(osp.basename(s.path), TIMESTAMP_FMT)
    snapshots.sort(key=lambda s: s.snapshot_time, reverse=True)
    return snapshots

def cleanup_snapshots(backupdir, keep=10, **ssh_args):
    """
    Looks in the snapshot directory of a backupdir, and cleans up the oldest snapshots
    until at most `keep` are left
    """
    snapshots = list_snapshots(backupdir, **ssh_args)
    logger.debug('Found snapshots: %s', snapshots)
    if len(snapshots) > keep:
        delete = snapshots[keep:]
        logger.info('Deleting %s snapshots: %s', len(delete), delete)
        for s in delete:
            rmtree(s.path, **ssh_args)
    else:
        logger.info('Found %s snapshots < %s to keep, not deleting any', len(snapshots), keep)


# ___________________________________________
# rsync commands

# -z: zip first, more processing power but better network
# -i: output a change-summary for all updates
# -r: recursive
# -v: verbose
# --delete-before: delete extraneous files from destination dirs;
#                  receiver deletes before transfer, not during
#                  this makes sure disk usage is never too large
# --size-only:     skip files that match in size
#                  Some mod times may differ because of manual copy
#                  operations in the past, no reason to recopy though
#                  THIS IS ONLY TRUE FOR MY PHOTO ALBUM BACKUP, NOT IN GENERAL
# -e: ssh expression if necessary

# trailing slash on src: WITHOUT means contents only, WITH means directory plus
# contents nested
# For this module, just always add a trailing slash and give a full path to the
# desired output directory

def compile_ssh_rsync(**ssh_args):
    ssh = compile_ssh(**ssh_args)
    # Turn it into an expression string for rsync, or empty if no options were found
    if len(ssh) > 1:
        ssh = '-e \'{0}\''.format(' '.join(ssh))
    else:
        ssh = ''
    return ssh

def copy_exact(src, dst, **ssh_args):
    """
    Copies src into dst so that dst will be exactly like src
    (i.e. rsync will delete files in dst that are no longer present
    in src)
    """
    if has_machine(src):
        raise NotImplementedError(
            'remote source {0} for rsync is not supported'
            .format(src)
            )
    if not src.endswith('/'): src += '/'
    rsync_cmd = str(
        'rsync'
        ' {dry}'
        ' -v -i -r -z'
        ' --size-only'
        ' --progress'
        ' --delete-before'
        ' {ssh}'
        ' {src} {dst}'
        ).format(
            src=src, dst=dst, ssh=compile_ssh_rsync(**ssh_args), dry='-n' if DRYMODE else ''
            )
    run_command(rsync_cmd, shell=True, dry=False, log_fn=logger.info)

def copy_update(src, dst, **ssh_args):
    """
    Copies src into dst so that dst will be updated with new files from src
    (i.e. rsync will NOT delete files in dst that are no longer present
    in src)
    """
    if has_machine(src):
        raise NotImplementedError(
            'remote source {0} for rsync is not supported'
            .format(src)
            )
    if not src.endswith('/'): src += '/'
    rsync_cmd = (
        'rsync'
        ' {dry}'
        ' -v -i -r -z'
        ' --size-only'
        ' --progress'
        ' {ssh}'
        ' {src} {dst}'
        .format(
            src=src, dst=dst, ssh=compile_ssh_rsync(**ssh_args), dry='-n' if DRYMODE else ''
            )
        )
    run_command(rsync_cmd, shell=True, dry=False, log_fn=logger.info)
