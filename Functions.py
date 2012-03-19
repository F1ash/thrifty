
import os.path, hashlib, time, pwd, random, string, rpm
char_set = string.ascii_letters + string.digits

USEREUID = os.geteuid()
USER_UID = pwd.getpwnam(os.getlogin())[2]
USER_GID = pwd.getpwnam(os.getlogin())[3]

ts = rpm.TransactionSet()
prelinkInstalled = True if len(ts.dbMatch('name', 'prelink')) else False
global PrelinkCache

def userName(uid) :
	res = -1
	try :
		res = pwd.getpwuid(uid)[0]
	except KeyError , err :
		print err
	finally : pass
	return res

def randomString(j = 1):
	return ''.join(random.sample(char_set, j))

def userId(str_):
	_raw = str_.split('/')
	if len(_raw) <= 1 :
		return USER_UID, USER_GID
	else :
		if _raw[0].isdigit() : u = int(_raw[0])
		else : u = USER_UID
		if _raw[1].isdigit() : g = int(_raw[1])
		else : g = USER_GID
		return u, g

def usersHOME_Detect():
	userHOMEs = []
	homeDIRs = []
	for dir_ in os.listdir('/home') :
		path = os.path.join('/home', dir_)
		if os.path.isdir(path) :
			homeDIRs.append(path)
	for item in pwd.getpwall() :
		if item[5] in homeDIRs :
			userHOMEs.append(item[5])
	return userHOMEs

def dateStamp():
	return time.strftime("%Y.%m.%d_%H:%M:%S", time.localtime()) + ' : '

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

def readExcludes(excludes, HOME = None):
	Excludes = []
	if os.path.isfile(excludes) :
		with open(excludes, 'rb') as f :
			path_ = f.read()
			path = path_.split('\n')
			for path_ in path :
				if path_ not in ('', ' ', '\n') and not path_.startswith('#') :
					if   path_.startswith('/') : Excludes.append(path_)
					elif path_.startswith('~/') and HOME is not None :
						Excludes.append(os.path.join(HOME, path_[2:]))
					else : pass
	return Excludes

def excludesActivate(HOME = None):
	Excludes = []
	if os.path.isfile('/etc/thrifty.excludes') :
		Excludes.append(readExcludes('/etc/thrifty.excludes', HOME))
	elif not USEREUID :
		with open('/etc/thrifty.excludes', 'wb') as f : pass
	path_ = os.path.join(HOME, '.config', 'thrifty', 'thrifty.excludes') \
			if HOME is not None else os.path.expanduser('~/.config/thrifty/thrifty.excludes')
	if os.path.isfile(path_) :
		Excludes.append(readExcludes(path_, HOME))
	elif USEREUID and HOME is not None :
		if not os.path.isdir(os.path.join(HOME, '.config', 'thrifty')) :
			os.makedirs(os.path.join(HOME, '.config', 'thrifty'))
		with open(path_, 'wb') as f : pass
	return Excludes

def readTargets():
	targets = []
	if os.path.isfile('/etc/thrifty.targets') :
		with open('/etc/thrifty.targets', 'rb') as f :
			path_ = f.read()
			path = path_.split('\n')
			for path_ in path :
				if path_ not in ('', ' ', '\n') and not path_.startswith('#') :
					targets.append(path_)
	return targets

def listDir(_dir, tab = '\t', Excludes = []):
	#print tab, _dir
	List = []
	try :
		for name in os.listdir(_dir) :
			path_ = os.path.join(_dir, name)
			if os.path.islink(path_) : continue	## links ignored
			if os.path.isfile(path_) :
				if path_ not in Excludes and path_ not in List : List.append(path_)
			elif os.path.isdir(path_) and path_ not in Excludes :
				List = List + listDir(path_, tab + '\t', Excludes)
	except OSError, err :
		print tab, err
	finally : pass
	return List

def listTDir(_dir, tab = '\t', Targets = []):
	#print tab, _dir
	List = []
	try :
		for name in os.listdir(_dir) :
			path_ = os.path.join(_dir, name)
			if os.path.islink(path_) : continue	## links ignored
			if os.path.isfile(path_) :
				if Targets == [] and path_ not in List :
					List.append(path_)
				else :
					for target in Targets :
						if path_.count(target) and path_ not in List :
							List.append(path_)
							break
			elif os.path.isdir(path_) :
				if Targets == [] : List = List + listTDir(path_, tab + '\t', Targets)
				elif path_.count(path_) :
					List = List + listTDir(path_, tab + '\t', Targets)
	except OSError, err :
		print tab, err
	finally : pass
	return List

def readFile(path_ = ''):
	if os.path.isfile(path_) :
		with open(path_, 'rb') as f :
			text = f.read()
	else : text = 'error in open file %s' % path_
	return text

def optimizeList(l = []):
	l.sort()
	for item in l :
		i = l.index(item)
		l[i] = os.path.abspath(item) + '/'
	idx = []
	i = 0
	for item in l :
		i += 1
		for item1 in l[i:] :
			if item1.startswith(item) :
				idx.append(l.index(item1))
	idx.reverse()
	#print l, idx
	for i in idx : del l[i]
	return l

def inList(name, list_):
	res = False
	for item in list_ :
		if name.startswith(item) :
			res = True
			break
	return res

def reversedFileState(name, _size):
	with open(name, 'rb') as f :
		bits = f.read(4)
	if bits == '\x7fELF' :
		exitCode = os.system('/usr/sbin/prelink -y ' + name + ' > /dev/shm/original_prog')
		if exitCode == 256 :
			_hash = exitCode
		else :
			_size = os.lstat('/dev/shm/original_prog').st_size
			_hash = fileHash('/dev/shm/original_prog')
		os.remove('/dev/shm/original_prog')
	else :
		_hash = fileHash(name)
	return _size, _hash

if prelinkInstalled :
	os.system('/usr/sbin/prelink -p > /dev/shm/prelink.cache')
	cache_raw = readFile('/dev/shm/prelink.cache')
	cache_str = cache_raw.split('\n')
	os.remove('/dev/shm/prelink.cache')
	_PrelinkCache = []
	for item in cache_str :
		chunks = item.split()
		#print chunks
		if len(chunks) > 0 :
			if len(chunks) > 1 and chunks[1].count('(not prelinkable)') :
				continue
			if chunks[0][-1:] == ':' :
				path = chunks[0][:-1]
			else :
				path = chunks[0]
			_PrelinkCache.append(path)
	PrelinkCache = []
	for item in _PrelinkCache :
		if item not in PrelinkCache :
			PrelinkCache.append(item)
	#print len(_PrelinkCache), len(PrelinkCache)
	del _PrelinkCache
