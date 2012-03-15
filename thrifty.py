#!/usr/bin/python

from Functions import *
import os, sys, os.path, rpm, tarfile
from stat import S_IRUSR, S_IWUSR, S_IRGRP, S_IWGRP, S_IROTH, S_IWOTH

def setFileState(name_):
	os.chmod(name_, S_IROTH | S_IWUSR |  S_IRGRP | S_IWGRP | S_IRUSR | S_IWOTH)
	os.chown(name_, USER_UID, USER_GID)

HELP = \
	'Description:\n\
	Utility for archiving or cleaning "rpmdb-out" files.\n\
	\n\
	thrifty [option]\n\
		0	-	very fast, ~200MB memory\n\
		1	-	fast, ~150MB memory\n\
		2	-	very slow, ~100MB memory\n\
		3	-	super fast, ~200MB !\n\
			This action backs up "rpmdb-out" or broken (file in rpmdb,\n\
			but checksum mismatched) files from own HOME only (user mode)\n\
			or /etc, /var/named/chroot, /usr/local, <all real HOME> (root mode).\n\
			Excludes specified in\n\
				/etc/thrifty.excludes (common)\n\
				~/.config/thrifty/thrifty.excludes (for HOME only)\n\
		-c (--clean) [dir0 dir1 .. dirN]\n\
			-	delete all (NOTE THIS!) "rpmdb-out" files from [dir0 dir1 .. dirN]\n\
			This means that you can remove a lot of icons, settings, etc files.\n\
			It`s a hard way (root mode only).\n\
			Targets specified in\n\
				/etc/thrifty.targets\n\
			If specified then the utility will be delete "rpmdb-out" files which contain\n\
			in path "target" string only, else -- delete all "rpmdb-out" files.\n\
		-t (--test) [dir0 dir1 .. dirN]\n\
			-	like --clean , but without removing files.\n\
			This action can be used to obtain the list of all "rpmdb-out" files.\n\
			And after editing it can be recorded in the /etc/thrifty.targets\n\
			for precise removal of files.\n\
		-b* (--broken*) [dir0 dir1 .. dirN]\n\
			-	get list of all broken "rpmdb" files to Log from dirNN.\n\
			*	mix from {M, O}, \n\
			-b	is a default mode of check : check size & hash of file;\n\
			M	add check of the file`s mode;\n\
			O	add check of the file`s uid & gid;\n\
			(Example: -bOM, -bMO, --brokenO, --brokenMO)\n\
		-f (--file) file\n\
			-	check the file (abspath) provided by some package and broken\n\
		-h (--help)\n\
			-	help\n\
	'

ts = rpm.TransactionSet()

class FileSniffer():
	def __init__(self, save_log_name = False, parent = None):
		self.stop = False
		self.task = {}
		self.save_log_name = save_log_name

	def __del__(self):
		self.stop = True

	def detectTask(self):
		self.specifiedDIRs = ('/etc', '/var/named/chroot', '/usr/local')
		if USEREUID :
			print 'UserMode'
			''' archiving own $HOME only '''
			name = os.path.expanduser('~')
			self.task[ name ] = os.path.basename(name) + '-some-' + dateStamp()[:19] + '.tar.bz2'
		else :
			print 'RootMode'
			''' archiving ['/etc', '/var/named/chroot', '/usr/local', <all real $HOME>] '''
			''' detect real HOMEs '''
			HOMEs = usersHOME_Detect()
			for name in HOMEs :
				self.task[ name ] = os.path.basename(name) + '-some-' + dateStamp()[:19] + '.tar.bz2'
			for name in self.specifiedDIRs :
				if os.path.isdir(name) :
					self.task[ name ] = os.path.basename(name) + '-some-' + dateStamp()[:19] + '.tar.bz2'

	def runTask(self, mode = 1):
		print self.task.keys()
		baseCreated = False
		log = os.path.join('/tmp', 'thrifty_'+ dateStamp()[:-3])
		for path in self.task.keys() :
			try :
				if self.stop : break
				print dateStamp(), 'create %s dirList beginning...' % path
				excludes = excludesActivate(None if path in self.specifiedDIRs else path)
				ArchiveFiles = listDir(path, Excludes = excludes)
				print dateStamp(), '%s dirList created' % path
				if mode in (0, 1) :
					print dateStamp(), 'beginning...'
					if not baseCreated :
						setOfAllPackageFiles = self.createSET(mode)
						baseCreated = True
					print dateStamp(), 'baseSet created'
					print dateStamp(), 'unMatched detecting...'
					unMatched = self.checkUnMatchedFiles(ArchiveFiles, setOfAllPackageFiles)
					print dateStamp(), 'unMatched created'
					for path_ in unMatched :
						if path_ in ArchiveFiles : ArchiveFiles.remove(path_)
					print dateStamp(), 'unMatched removed'
				else :
					print dateStamp(), 'beginning...'
					toArchive = []
					if mode == 2 :
						for fileName in ArchiveFiles :
							res = self.checkWarningFile(fileName, 1)
							if res is not None and fileName not in toArchive : toArchive.append(fileName)
						ArchiveFiles = toArchive
					else :
						self.getFI(mode = 0, dirList = ArchiveFiles)
					print dateStamp(), 'matched fileList created'
				nameArchive = self.task[path]
				print dateStamp(), 'archivator running...'
				self.archivator(ArchiveFiles, nameArchive)
				print dateStamp(), '%s archivating complete' % path
			except KeyboardInterrupt, err :
				print err
				self.stop = True
			except IOError, err :
				print err
			finally : pass
			if self.stop : break
			with open(log, 'ab') as f :
				for path_ in ArchiveFiles :
					f.write(path_ + '\n')
		if os.path.isfile(log) : setFileState(log)
		if self.save_log_name :
			name_ = '/dev/shm/thrifty.lastTask'
			with open(name_, 'wb') as f :
				f.write(log)
			if os.path.isfile(name_) : setFileState(name_)
		print 'Log in : %s' % log

	def runFastProc(self):
		self.detectTask()
		self.runTask(0)

	def runNormalProc(self):
		self.detectTask()
		self.runTask(1)

	def runSlowProc(self):
		self.detectTask()
		self.runTask(2)

	def runBOMBProc(self):
		self.detectTask()
		self.runTask(3)

	def cleanTask(self, dirPath = [], test = False):
		print "CleanUp :\n", dirPath
		try :
			print dateStamp(), 'create dirList beginning...'
			targets = readTargets()
			CleanedFiles = []
			for path_ in dirPath :
				CleanedFiles = CleanedFiles + listTDir(path_, Targets = targets)
			print dateStamp(), 'dirList created'
			self.getFI(mode = 0, dirList = CleanedFiles, sensitivity = False)
			print dateStamp(), 'matched fileList created'
			count, size = self.cleaner(CleanedFiles, test)
			print dateStamp(), 'Cleaning is complete.\n'
			print 'Removed %s files; Released %s Byte(s)\n' % (count, size)
			log = os.path.join('/tmp', 'thrifty_'+ dateStamp()[:-3])
			with open(log, 'ab') as f :
				for path_ in CleanedFiles :
					f.write(path_ + '\n')
			if os.path.isfile(log) : setFileState(log)
			if self.save_log_name :
				name_ = '/dev/shm/thrifty.lastTask'
				with open(name_, 'wb') as f :
					f.write(log + '\n' + str(count)  + '\n' + str(size))
				if os.path.isfile(name_) : setFileState(name_)
			print 'Log in : %s' % log
		except KeyboardInterrupt, err :
			print err
			self.stop = True
		except IOError, err :
			print err
		finally : pass

	def cleaner(self, cleaned = [], test = False):
		count = 0
		size = 0
		for path_ in cleaned :
			if not self.stop and os.path.isfile(path_) :
				size += os.path.getsize(path_)
				if not test : os.remove(path_)
				count += 1
			elif self.stop : break
		return count, size

	def getFI(self, packet = None, fileName = '', mode = 1, dirList = [], sensitivity = True):
		mi = ts.dbMatch() if packet is None else ts.dbMatch('name', packet)
		if mode :
			## VARIANT I (data from rpm.hdr class)
			matched = []
			for h in mi.__iter__() :
				if self.stop : break
				if fileName in h['FILENAMES'] :
					packageName = h['name'] + '-' + h['version'] + '-' + h['release']
					matched.append((packageName, fileName, h[1035][h['FILENAMES'].index(fileName)]))
				#else : print 'Not found'
			return matched
		else :
			## VARIANT II (data from rpm.fi object) Memory BOMB !!!
			for h in mi.__iter__() :
				if self.stop : break
				fi = h.fiFromHeader()
				for item in fi.__iter__() :
					if self.stop : break
					#print item
					name = item[0]
					if name in dirList :
						if not sensitivity :
							dirList.remove(name)
						elif fileHash(name) == item[12] :
							dirList.remove(name)

	def brokenTask(self, dirPath = [], control = [False, False]):
		print "Get broken in :\n", dirPath
		try :
			print dateStamp(), 'create dirList beginning...'
			Files = []
			for path_ in dirPath :
				Files = Files + listDir(path_)
			print dateStamp(), 'dirList created'
			matched = []
			self.getBroken(matched, Files, control)
			print dateStamp(), 'matched fileList created'
			log = os.path.join('/tmp', 'thrifty_'+ dateStamp()[:-3])
			with open(log, 'ab') as f :
				for item in matched :
					f.write(item)
			if os.path.isfile(log) : setFileState(log)
			if self.save_log_name :
				name_ = '/dev/shm/thrifty.lastTask'
				with open(name_, 'wb') as f :
					f.write(log)
				if os.path.isfile(name_) : setFileState(name_)
			print 'Log in : %s' % log
		except KeyboardInterrupt, err :
			print err
			self.stop = True
		except IOError, err :
			print err
		finally : pass

	def getBroken(self, matched, dirList = [], control = [False, False]):
		mi = ts.dbMatch()
		for h in mi.__iter__() :
			if self.stop : break
			fi = h.fiFromHeader()
			for item in fi.__iter__() :
				if self.stop : break
				#a = (item[0], item[1], item[2], item[3], item[10], item[11], item[12])
				#b = (fi.FN(), fi.FSize(), fi.FMode(), \
				#	fi.FMtime(), fi.FUser(), fi.FGroup(), fi.MD5())
				#if a != b : print a, '\n', b
				name = fi.FN()
				if name in dirList :
					fileState = os.stat(name)
					badFile = False
					if fileHash(name) != fi.MD5() or fileState.st_size != fi.FSize() :
						badFile = True
					if not badFile and control[0] and (fileState.st_mode != fi.FMode()) :
						badFile = True
					if not badFile and control[1] and \
							(userName(fileState.st_uid) != fi.FUser() or \
							userName(fileState.st_gid) != fi.FGroup()) :
						badFile = True
					#if not badFile and control[3] and (int(fileState.st_mtime) != fi.FMtime()) :
					#	badFile = True
					if badFile :
						packageName = h['name'] ##+ '-' + h['version'] + '-' + h['release']
						matched.append(''.join((name, ' ', packageName, '\n')))

	def checkWarningFile(self, absPath, mode, infoShow = False):
		toArchive = None
		self._data = ('','','')
		if not self.stop :
			res = self.getFI(None, absPath, mode)
			if infoShow :
				print res
				_fileHash = fileHash(absPath)
			if len(res) == 1 :
				toArchive = None if _fileHash == res[0][2] else res[0][1]
				if infoShow :
					print 'Is packaged:', absPath, 'Safe' if toArchive is None else 'broken'
					self._data = (res[0][0], res[0][2], _fileHash if _fileHash is not None else '--')
			elif len(res) > 1 :
				if infoShow :
					print 'Warning: multipackage %s' % absPath
					self._data = ('Multipackaged', '--', _fileHash if _fileHash is not None else '--')
			elif len(res) < 1 :
				if infoShow :
					print 'Not packaged:', absPath
					self._data = ('Not packaged', '--', _fileHash if _fileHash is not None else '--')
				toArchive = absPath
		return toArchive

	def createSET(self, mode = 1):
		s = {}
		mi = ts.dbMatch()
		if mode :
			## fast /2min55sec:~145MB/
			for h in mi :
				if self.stop : break
				i = 0
				for name in h['FILENAMES'] :
					if self.stop : break
					#print name, h[1035][i]
					if os.path.isfile(name) : s[name] = h[1035][i]
					i += 1
		else :
			## very fast /1min25sec:~200MB/
			for h in mi :
				if self.stop : break
				fi = h.fiFromHeader()
				for item in fi.__iter__() :
					if self.stop : break
					#print item
					name = item[0]
					if os.path.isfile(name) : s[name] = item[12]
		return s

	def checkUnMatchedFiles(self, fileList, baseSet):
		unMatched = []
		for fileName in fileList :
			if self.stop : break
			if fileName in baseSet.keys() :
				h = fileHash(fileName)
				if h is None or h == baseSet[fileName] :
					unMatched.append(fileName)
		return unMatched

	def archivator(self, archList, nameArch):
		if self.stop : return
		tar = tarfile.open(os.path.join('/tmp', nameArch), 'w:bz2')
		for fileName in archList :
			if self.stop : break
			try :
				tar.add(fileName)
			except IOError, err : print err
			finally : pass
		tar.close()
		if self.stop : os.remove(nameArch)

def __del__():
	global job
	job.__del__()

if __name__ == '__main__':
	parameters = sys.argv
	mode_ = parameters[1] if len(parameters) > 1 else 'broken'
	save_log_name = False
	if mode_.startswith('G:') :
		save_log_name = True
		mode_raw = mode_.split('G:')[1]
		userID, mode = mode_raw.split('::')
		USER_UID, USER_GID = userId(userID)
	else : mode = mode_
	global job
	try :
		if mode.isdigit() :
			job = FileSniffer(save_log_name)
			job.detectTask()
			job.runTask(int(mode))
		elif mode in ('-f', '--file') :
			fileName = os.path.abspath(parameters[2]) if len(parameters)>2 else ''
			job = FileSniffer()
			job.checkWarningFile(fileName, 1, True)
			if save_log_name :
				name_ = '/dev/shm/thrifty.lastTask'
				with open(name_, 'ab') as f :
					for str_ in job._data :
						f.write(str_ + '\n')
				if os.path.isfile(name_) : setFileState(name_)
		elif mode in ('-c', '--clean') :
			if USEREUID :
				print 'RootMode necessary for clean.'
			else :
				dirPath = parameters[2:] if len(parameters)>2 else []
				job = FileSniffer(save_log_name)
				job.cleanTask(dirPath)
		elif mode in ('-t', '--test') :
			if USEREUID :
				print 'RootMode necessary for clean.'
			else :
				dirPath = parameters[2:] if len(parameters)>2 else []
				job = FileSniffer(save_log_name)
				job.cleanTask(dirPath, True)
		elif mode.startswith('-b') or mode.startswith('--broken') :
			if USEREUID :
				print 'RootMode necessary for search broken files.'
			else :
				if mode.startswith('-b') :
					level = mode[2:]
				else :
					level = mode[8:]
				control = [False, False]
				if 'M' in level : control[0] = True
				if 'O' in level : control[1] = True
				dirPath = parameters[2:] if len(parameters)>2 else []
				job = FileSniffer(save_log_name)
				job.brokenTask(dirPath, control)
		elif mode in ('-h', '--help') :
			print HELP
		else :
			print 'broken command : %s\n%s' % (parameters, HELP)
	except KeyboardInterrupt , err :
		print err
	finally : print 'Bye...'
