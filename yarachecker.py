import yara
import os
import fnmatch

class YaraChecker(object):

    def __init__(self):
        self.ext_filter = "*.json"
        if os.path.exists('./rules.save'):
           self.load_rules()
        else:
            self.rules = yara.compile('./index.yar')
            rs = self.rules
            rs.save("./rules.save")
    
    def load_rules(self):
        #load the rules of yara
        self.rules =yara.load("./rules.save")
        return

    def run_matches(self, fpath):
        matches = self.rules.match(fpath, callback=self.print_match)
        
    def print_match(self, data):
        if data['matches'] == True:
            print(str(data['rule']) +' '+str(data['strings']))
        yara.CALLBACK_CONTINUE
    

    def run_yara(self, path='./scanfolder/'):
        res = []
        files = os.listdir(path)
        for fir in files:
            with open(path+fir, 'rb') as f:
                print('Parsing the file '+str(fir))
                res.append( self.run_matches(path+fir))
        return res

