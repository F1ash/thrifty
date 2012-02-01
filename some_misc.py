#!/usr/bin/python

from Functions import *
import sys, os.path, rpm, tarfile

ts = rpm.TransactionSet()

class FileSniffer():
	def __init__(self, parent = None):
		self.stop = False
		self.task = {}

	def __del__(self):
		self.stop = True

	def detectTask(self):
		if os.geteuid() :
			print 'UserMode'
			''' archivate own $HOME only '''
			name = os.path.expanduser('~')
			self.task[ name ] = os.path.basename(name) + '-some-' + dateStamp()[:19] + '.tar.bz2'
		else :
			print 'RootMode'
			''' archivate ['/etc', '/var/named/chroot', '/usr/local', <all real $HOME>] '''
			''' detect real HOMEs '''
			HOMEs = []
			## TODO : detecting HOMEs
			for name in HOMEs :
				self.task[ name ] = os.path.basename(name) + '-some-' + dateStamp()[:19] + '.tar.bz2'
			for name in ('/etc', '/var/named/chroot', '/usr/local') :
				if os.path.isdir(name) :
					self.task[ name ] = os.path.basename(name) + '-some-' + dateStamp()[:19] + '.tar.bz2'

	def runTask(self, mode = 1):
		print self.task.keys()
		for path in self.task.keys() :
			try :
				if self.stop : break
				print dateStamp(), 'create %s dirList beginning...' % path
				ArchiveFiles = listDir(path)
				print dateStamp(), '%s dirList created' % path
				if mode in (0, 1) :
					print dateStamp(), 'beginning...'
					setOfAllPackageFiles = self.createSET(mode)
					print dateStamp(), 'baseSet created'
					print dateStamp(), 'unMatched detecting...'
					unMatched = self.checkUnMatchedFiles(ArchiveFiles, setOfAllPackageFiles)
					print dateStamp(), 'unMatched created'
					for path_ in unMatched :
						if path_ in ArchiveFiles : ArchiveFiles.remove(path_)
					print dateStamp(), 'unMatched removed'
					#for path_ in ArchiveFiles : print path_
					#print dateStamp(), 'matched printed'
					nameArchive = self.task[path]
					print dateStamp(), 'archivator running...'
					self.archivator(ArchiveFiles, nameArchive)
					print dateStamp(), '%s archivating complete' % path
				else :
					print dateStamp(), 'beginning...'
					toArchive = []
					nameArchive = self.task[path]
					mode = 1 if mode == 2 else 0
					for fileName in ArchiveFiles :
						res = self.checkWarningFile(fileName, mode)
						if res is not None and fileName not in toArchive : toArchive.append(fileName)
					print dateStamp(), 'matched fileList created'
					self.archivator(toArchive, nameArchive)
					print dateStamp(), '%s archivating complete' % path
			except KeyboardInterrupt, err :
				print err
				self.stop = True
			except IOError, err :
				print err
			finally : pass

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

	def getFI(self, packet, fileName, absPathMode = False, mode = 1):
		mi = ts.dbMatch() if packet is None else ts.dbMatch('name', packet)
		matched = []
		if fileName == os.path.basename(fileName) : absPathMode = False
		if mode :
			## VARIANT I (data from rpm.hdr class)
			for h in mi.__iter__() :
				if self.stop : break
				#print "%s-%s-%s" % (h['name'], h['version'], h['release'])
				packageName = h['name'] + '-' + h['version'] + '-' + h['release']
				i = 0
				for name in h['FILENAMES'] :
					if self.stop : break
					if os.path.isfile(name) and (name if absPathMode else os.path.basename(name)) == fileName :
						#print name, h[1035][i]
						matched.append((packageName, name, h[1035][i]))
						#break
					i += 1
				#else : print 'Not found'
		else :
			## VARIANT II (data from rpm.fi object) Memory BOMB !!!
			for h in mi.__iter__() :
				if self.stop : break
				fi = h.fiFromHeader()
				for item in fi.__iter__() :
					if self.stop : break
					#print item
					name = item[0]
					if os.path.isfile(name) and (name if absPathMode else os.path.basename(name)) == fileName :
						packageName = h['name'] + '-' + h['version'] + '-' + h['release'] + '.' + h['arch']
						#print packageName, name, item[12]
						matched.append((packageName, name, item[12]))
						#break
				#else : print 'Not found'
		return matched

	def checkWarningFile(self, absPath, mode):
		toArchive = None
		if not self.stop : res = self.getFI(None, absPath, True, mode)
		else : return None
		#print res, 'in check'
		if len(res) > 1 : print 'Warning: multipackage %s' % absPath
		elif len(res) < 1 :
			print 'Not packaged:', absPath
			toArchive = absPath
		else :
			toArchive = None if fileHash(absPath) == res[0][2] else res[0][1]
			print 'Is packaged:', absPath, 'Safe' if toArchive is None else 'Brocken'
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

	def archivator(self, archList, nameArch, excludes = ''):
		if self.stop : return
		tar = tarfile.open(nameArch, 'w:bz2')
		if not os.path.isfile(excludes) :
			Excludes = []
		else :
			with open(excludes) as f :
				path_ = f.read()
				path = path_.split('\n')
				for path_ in path :
					if path_ not in ('', ' ', '\n') :
						Excludes.append(path_)
		for fileName in archList :
			if self.stop : break
			if fileName not in Excludes :
				try :
					tar.add(fileName)
				except IOError, err : print err
				finally : pass
		tar.close()
		if self.stop : os.remove(nameArch)

if __name__ == '__main__':
	mode = sys.argv[1]
	try :
		if mode.isdigit() :
			job = FileSniffer()
			job.detectTask()
			job.runTask(int(mode))
		elif mode in ('-f', '--file') :
			fileName_ = sys.argv[2]
			fileName = fileName_[2:] if fileName_[:2] in ['~/', '*/', './', '?/'] else fileName_
			fileName = fileName[1:] if fileName.startswith('/') else fileName
			job = FileSniffer()
			job.checkWarningFile(fileName if len(res)<1 else res[0][1], 0)
		elif mode in ('-h', '--help') :
			print \
	'Description: thrifty [option] [[param]]\n\
	0	-	very fast, ~200MB memory\n\
	1	-	fast, ~150MB memory\n\
	2	-	very slow, ~100MB memory\n\
	<N>\n\
		-	deprecated, memory BOMB !\n\
	-f (--file) file\n\
		-	check the file provided by some package and brocken\n\
	-h (--help)\n\
		-	help\n\
	'
		else :
			print 'Brocken command'
	except KeyboardInterrupt , err :
		print err
	finally : print 'Bye...'
