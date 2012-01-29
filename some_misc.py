#!/usr/bin/python

from yum.rpmsack import RPMDBPackageSack
import sys, os.path, rpm, hashlib, time, tarfile

ts = rpm.TransactionSet()
sack = RPMDBPackageSack('/')

class NoUsedCase(Exception): pass

def getFI(packet, fileName, absPathMode = False):
	mi = ts.dbMatch() if packet is None else ts.dbMatch('name', packet)
	matched = []
	if fileName == os.path.basename(fileName) : absPathMode = False
	for h in mi.__iter__() :
		## VARIANT I (data from rpm.hdr class)
		#print "%s-%s-%s" % (h['name'], h['version'], h['release'])
		packageName = h['name'] + '-' + h['version'] + '-' + h['release']
		i = 0
		for name in h['FILENAMES'] :
			if os.path.isfile(name) and (name if absPathMode else os.path.basename(name)) == fileName :
				#print name, h[1035][i]
				matched.append((packageName, name, h[1035][i]))
				#break
			i += 1
		#else : print 'Not found'

		'''
		## VARIANT II (data from rpm.fi object) Memory BOMB !!!
		fi = h.fiFromHeader()
		for item in fi.__iter__() :
			#print item
			name = item[0]
			if os.path.isfile(name) and (name if absPathMode else os.path.basename(name)) == fileName :
				packageName = h['name'] + '-' + h['version'] + '-' + h['release'] + '.' + h['arch']
				#print packageName, name, item[12]
				matched.append((packageName, name, item[12]))
				#break
		#else : print 'Not found'
		'''
	return matched

def _yumProvidesFile(fileName_):
	#sack = RPMDBPackageSack('/')
	#for p in sack.simplePkgList():
	#	print p
	#print fileName_[:2], fileName_[2:] if fileName_[:2] in ['~/', '*/', './', '?/'] else fileName_
	fileName = fileName_[2:] if fileName_[:2] in ['~/', '*/', './', '?/'] else fileName_
	name = fileName[1:] if fileName.startswith('/') else fileName
	#print sack.searchProvides(name)
	#print sack.searchAll(name)
	data = sack.getProvides(name)
	if len(data) > 1 : raise NoUsedCase, 'RPMDBError'
	packageName = data[data.keys()[0]][0][0] if len(data) else None
	return packageName, name

def fileHash(path_):
	m = hashlib.sha256()
	error = False
	try :
		with open(path_, 'rb') as f :
			while True :
				chunk = f.read(1024)
				if len(chunk) > 0 : m.update(chunk)
				else : break ## EOF
	except IOError, err :
		print err
		error = True
	finally : pass
	return None if error else m.hexdigest()

def checkWarningFile(absPath):
	toArchive = None
	#fileName = os.path.basename(absPath)
	#packet, fileName = _yumProvidesFile(fileName)
	#print packet, fileName, 'in check'
	res = getFI(None, absPath, True)
	#print res, 'in check'
	if len(res) > 1 : print 'Warning: multipackage %s' % absPath
	elif len(res) < 1 :
		print 'Not packaged:', absPath
		toArchive = absPath
	else :
		toArchive = None if fileHash(absPath) == res[0][2] else res[0][1]
		print 'Is packaged:', absPath, 'True' if toArchive is None else 'Danger'
	return toArchive

def checkProcessingFile(fileList):
	mi = ts.dbMatch()
	unMatched = []
	for h in mi :
		fi = h.fiFromHeader()
		for fileName in fileList :
			unUsed = False
			for item in fi.__iter__() :
				#print item
				name = item[0]
				if os.path.isfile(name) and name == fileName :
					#packageName = h['name'] + '-' + h['version'] + '-' + h['release'] + '.' + h['arch']
					#print packageName, name, item[12]
					if fileHash(fileName) == item[12] :
						unUsed = True	## checkSumm equel, not archivated
					break
			if unUsed and fileName not in unMatched :
				print fileName
				unMatched.append(fileName)
		for fileName in unMatched and fileName in fileList : fileList.remove(fileName)
	return unMatched

def createSET():
	s = {}
	mi = ts.dbMatch()
	for h in mi :
		'''
		## very fast /1min25sec:~200MB/
		fi = h.fiFromHeader()
		for item in fi.__iter__() :
			#print item
			name = item[0]
			if os.path.isfile(name) : s[name] = item[12]
		'''
		## fast /2min55sec:~145MB/
		i = 0
		for name in h['FILENAMES'] :
			#print name, h[1035][i]
			if os.path.isfile(name) : s[name] = h[1035][i]
			i += 1
	return s

def checkUnMatchedFiles(fileList, baseSet):
	unMatched = []
	for fileName in fileList :
		if fileName in baseSet.keys() :
			h = fileHash(fileName)
			if h is None or h == baseSet[fileName] :
				unMatched.append(fileName)
	return unMatched

def listDir(_dir, tab = '\t'):
	#print tab, _dir
	List = []
	try :
		for name in os.listdir(_dir) :
			path_ = os.path.join(_dir, name)
			if os.path.islink(path_) : continue
			if os.path.isfile(path_) :
				#print tab + '\t', path_
				#res = checkWarningFile(path_)
				#if res is not None : List.append(res)
				List.append(path_)
			elif os.path.isdir(path_) :
				List = List + listDir(path_, tab + '\t')
				pass
	except OSError, err :
		print tab, err
	finally : pass
	return List

def archivator(archList, nameArch, excludes = ''):
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
		if fileName not in Excludes :
			try :
				tar.add(fileName)
			except IOError, err : print err
			finally : pass
	tar.close()

def dateStamp():
	return time.strftime("%Y.%m.%d_%H:%M:%S", time.localtime()) + ' : '

if __name__ == '__main__':
	'''
	fileName = sys.argv[1]
	packet, fileName = _yumProvidesFile(fileName)
	print packet, fileName
	res = getFI(packet, fileName)
	print res
	print checkWarningFile(fileName if len(res)<1 else res[0][1]), 'checked'
	'''
	if os.geteuid() : print 'UserMode'
	else : print 'RootMode'

	print dateStamp(), 'create dirList beginnig...'
	ArchiveFiles = listDir('/etc')
	print dateStamp(), 'dirList created'
	
	'''## very fast, ~200MB memory
	print dateStamp(), 'beginnig...'
	setOfAllPackageFiles = createSET()
	print dateStamp(), 'baseSet created'
	unMatched = checkUnMatchedFiles(ArchiveFiles, setOfAllPackageFiles)
	print dateStamp(), 'unMatched created'
	for path_ in unMatched :
		if path_ in ArchiveFiles : ArchiveFiles.remove(path_)
	print dateStamp(), 'unMatched removed'
	for path_ in ArchiveFiles : print path_
	print dateStamp(), 'matched printed'
	nameArchive = 'etc-some-' + dateStamp()[:19] + '.tar.bz2'
	print dateStamp(), 'archivator runnind...'
	archivator(ArchiveFiles, nameArchive)
	print dateStamp(), 'archivating complete'
	'''

	## very slow, ~100MB memory
	print dateStamp(), 'beginnig...'
	toArchive = []
	nameArchive = 'etc-some-' + dateStamp()[:19] + '.tar.bz2'
	for fileName in ArchiveFiles :
		res = checkWarningFile(fileName)
		if res is not None and fileName not in toArchive : toArchive.append(fileName)
	print dateStamp(), 'matched fileList created'
	archivator(toArchive, nameArchive)
	print dateStamp(), 'complete'
