
import os.path, hashlib, time, pwd

USEREUID = os.geteuid()
USER_UID = pwd.getpwnam(os.getlogin())[2]
USER_GID = pwd.getpwnam(os.getlogin())[3]

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
		with open() as f :
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
				if path_ not in Excludes : List.append(path_)
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
				if Targets == [] :
					List.append(path_)
				else :
					for target in Targets :
						if path_.count(target) :
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
