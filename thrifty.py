#!/usr/bin/python

from Functions import *
import os, sys, os.path, tarfile, stat
from stat import S_IRUSR, S_IWUSR, S_IRGRP, S_IWGRP, S_IROTH, S_IWOTH

def setFileState(name_):
	os.chmod(name_, S_IROTH | S_IWUSR |  S_IRGRP | S_IWGRP | S_IRUSR | S_IWOTH)
	os.chown(name_, USER_UID, USER_GID)

HELP = \
	'Description:\n\
	Utility for archiving or cleaning "rpmdb-out" files.\n\
	\n\
	thrifty [option]\n\
		0	-	very fast\n\
		1	-	fast\n\
		2	-	very slow\n\
		3	-	super fast\n\
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
			*	mix from {M, O, T}, \n\
			-b	is a default mode of check : check size & hash of file;\n\
			M	add check of the file`s mode;\n\
			O	add check of the file`s uid & gid;\n\
			T	add check of the file`s mtime;\n\
			(Example: -bOM, -bMO, --brokenO, --brokenMTO)\n\
		-f (--file) file\n\
			-	check the file (abspath) provided by some package and broken\n\
		-h (--help)\n\
			-	help\n\
	'

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

	def brokenTask(self, dirPath = [], control = [False, False, False]):
		print "Get broken in :\n", dirPath
		try :
			print dateStamp(), 'create dirList beginning...'
			#Files = []
			#for path_ in dirPath :
			#	Files = Files + listDir(path_)
			Files = optimizeList(dirPath)
			print dateStamp(), 'dirList created'
			matched = []
			self.getBroken(matched, Files, control)
			print dateStamp(), 'matched fileList created'
			log = os.path.join('/tmp', 'thrifty_'+ dateStamp()[:-3])
			with open(log, 'wb') as f :
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

	def getBroken(self, matched, dirList = [], control = [False, False, False]):
		'''
		http://www.rpm.org/max-rpm/s1-rpm-verify-we-lied.html#AEN4498
		'''
		mi = ts.dbMatch()
		for h in mi.__iter__() :
			if self.stop : break
			fi = h.fiFromHeader()
			for item in fi.__iter__() :
				if self.stop : break
				''' 'BN', 'DC', 'DN', 'DX', \
					'Digest', 'FC', 'FClass', 'FColor', \
					'FFlags', 'FGroup', \
					'FLink', 'FMode', 'FMtime', 'FN', \
					'FRdev', 'FSize', 'FState', 'FUser', \
					'FX', 'MD5', 'VFlags' '''
				name = fi.FN()
				if inList(name, dirList) :
					if not os.path.lexists(name) :
						# file or dir from package not exist in system
						packageName = h['name']   ##+ '-' + h['version'] + '-' + h['release']
						matched.append(''.join((name, ' ', packageName, ' NotExist', '\n')))
						#print name, 'not exist in system'
						break
					itemState = os.lstat(name)
					isLink = True if stat.S_ISLNK(itemState.st_mode) else False
					isDir = True if stat.S_ISDIR(itemState.st_mode) else False
					isReg = True if stat.S_ISREG(itemState.st_mode) else False
					if isLink :
						head, tail = os.path.split(name)
						if fi.FLink().startswith('/') :
							link = fi.FLink()
						elif fi.FLink().startswith('../') :
							_link = fi.FLink()
							while _link.startswith('../') :
								_link = _link[3:]
								head = os.path.split(head)[0]
							link = os.path.join(head, _link)
						elif fi.FLink().startswith('./') :
							link = os.path.join(head, os.path.split(fi.FLink())[1])
						else :
							link = os.path.join(head, fi.FLink())
						if link != os.path.realpath(name) :
							# link from package not correct
							packageName = h['name']   ##+ '-' + h['version'] + '-' + h['release']
							matched.append(''.join((name, ' ', packageName, ' LinkIncorrect', '\n')))
							#print name
							#print fi.FLink(), os.path.realpath(name), link
							break
					badFile = False
					error = ''
					if not isDir and not isLink and isReg :
						_size, sha256sum = reversedFileState(name, itemState.st_size) \
							if prelinkInstalled and name in PrelinkCache \
							else (itemState.st_size, fileHash(name))
						#if not isDir and not isLink and isReg :
						if (sha256sum != fi.MD5() or _size != fi.FSize()) :
							# repeat for lost in prelink.cache
							# 256 is fail exitCode of `prelink -y <name>`
							if str(sha256sum) == '256' :
								badFile = True
							else :
								_size, sha256sum = reversedFileState(name, itemState.st_size)
								if str(sha256sum) != '256' :
									if (sha256sum != fi.MD5() or _size != fi.FSize()) :
										badFile = True
								else : badFile = True
							if badFile :
								#print name
								#print fi.FSize(), fi.MD5()
								#print _size, sha256sum
								error = 'Hash or Size Mismatched'
					if not badFile and control[0] and \
							(int(itemState.st_mode) != fi.FMode()) :
						#print name
						#print itemState.st_mode, ':', fi.FMode()
						error = 'FileMode Error'
						badFile = True
					if not badFile and control[1] and \
							(userName(itemState.st_uid) != fi.FUser() or \
							userName(itemState.st_gid) != fi.FGroup()) :
						#print name
						#print userName(itemState.st_uid), fi.FUser(), ':', \
						#	  userName(itemState.st_gid), fi.FGroup()
						error = 'Owners Mismatched'
						badFile = True
					if not badFile and not isDir and not isLink \
							and isReg and control[2] and \
							(int(itemState.st_mtime) != fi.FMtime()) :
						#print name
						#print int(itemState.st_mtime), fi.FMtime()
						error = 'FileMtime Mismatched'
						badFile = True
					if badFile :
						#print item
						packageName = h['name'] if sha256sum != 256 \
							else ' at least one of file`s dependencies has changed since prelinking'
						##+ '-' + h['version'] + '-' + h['release']
						matched.append(''.join((name, ' ', packageName, ' ', error, '\n')))
						break

	def verifyFile(self, fileName):
		mi = ts.dbMatch()
		data = {}
		multi = 0
		for h in mi.__iter__() :
			if fileName not in h['FILENAMES'] : continue
			fi = h.fiFromHeader()
			for item in fi.__iter__() :
				name = fi.FN()
				if name == fileName :
					#print item
					itemState = os.lstat(name)
					isLink = True if stat.S_ISLNK(itemState.st_mode) else False
					isDir = True if stat.S_ISDIR(itemState.st_mode) else False
					isReg = True if stat.S_ISREG(itemState.st_mode) else False
					dev = itemState.st_dev
					if isLink :
						head, tail = os.path.split(name)
						if fi.FLink().startswith('/') :
							link = fi.FLink()
						elif fi.FLink().startswith('../') :
							_link = fi.FLink()
							while _link.startswith('../') :
								_link = _link[3:]
								head = os.path.split(head)[0]
							link = os.path.join(head, _link)
						elif fi.FLink().startswith('./') :
							link = os.path.join(head, os.path.split(fi.FLink())[1])
						elif fi.FLink() != '' :
							link = os.path.join(head, fi.FLink())
						else : link = '--'
						data['linkP'] = link
						data['linkR'] = os.path.realpath(name)
					if not isDir and not isLink and isReg :
						_size, sha256sum = reversedFileState(name, itemState.st_size) \
							if prelinkInstalled and name in PrelinkCache \
							else (itemState.st_size, fileHash(name))
						#if not isDir and not isLink and isReg :
						if (sha256sum != fi.MD5() or _size != fi.FSize()) :
							# repeat for lost in prelink.cache
							if str(sha256sum) != '256' :
								__size, _sha256sum = reversedFileState(name, itemState.st_size)
								if str(_sha256sum) != '256' :
									_size = __size
									sha256sum = _sha256sum
						data['sizeR'] = _size
						data['hashR'] = sha256sum
						data['sizeP'] = fi.FSize()
						data['hashP'] = fi.MD5()
					data['modeR'] = int(itemState.st_mode)
					data['modeP'] = fi.FMode()
					data['uidR'] = userName(itemState.st_uid)
					data['uidP'] = fi.FUser()
					data['gidR'] = userName(itemState.st_gid)
					data['gidP'] = fi.FGroup()
					if not isDir and not isLink and isReg :
						data['mtimeR'] = int(itemState.st_mtime)
						data['mtimeP'] = fi.FMtime()
					packageName = h['name'] + '-' + h['version'] + '-' + h['release']
					data['package'] = packageName
					break
			multi += 1
			#print data, multi
		return data, multi

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
			#job.checkWarningFile(fileName, 1, True)
			name_ = '/dev/shm/thrifty.lastTask'
			if not os.access(fileName, os.R_OK) :
				print 'Permission denied.'
				with open(name_, 'wb') as f :
					f.write('package:Permissin denied or File not exist.\nmulti:0')
			else :
				data, multi = job.verifyFile(fileName)
				with open(name_, 'wb') as f :
					for item in data.iterkeys() :
						print '%s : %s' % (item, data[item])
						if save_log_name :
							f.write('%s:%s\n' % (item, str(data[item])))
					f.write('multi:' + str(multi))
				if multi > 1 : print 'WARNING: not unique data in rpmDB (%s records)' % multi
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
				control = [False, False, False]
				if 'M' in level : control[0] = True
				if 'O' in level : control[1] = True
				if 'T' in level : control[2] = True
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
