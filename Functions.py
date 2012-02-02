
import os.path, hashlib, time

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

def readExcludes(excludes):
		if not os.path.isfile(excludes) :
			Excludes = []
		else :
			with open(excludes) as f :
				path_ = f.read()
				path = path_.split('\n')
				for path_ in path :
					if path_ not in ('', ' ', '\n') :
						Excludes.append(path_)
		return Excludes

def listDir(_dir, tab = '\t'):
	#print tab, _dir
	List = []
	try :
		for name in os.listdir(_dir) :
			path_ = os.path.join(_dir, name)
			if os.path.islink(path_) : continue
			if os.path.isfile(path_) :
				List.append(path_)
			elif os.path.isdir(path_) :
				List = List + listDir(path_, tab + '\t')
				pass
	except OSError, err :
		print tab, err
	finally : pass
	return List
