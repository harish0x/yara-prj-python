from flask import Flask, flash, request, redirect, url_for,render_template ,send_from_directory
import os
from flask.templating import render_template_string
import yara
from werkzeug.utils import secure_filename
from pathlib import Path
location='/home/harishankar/v2/scanfile'

app = Flask(__name__, template_folder='templates')
app.config['location'] = location



@app.route('/uploade')
def upload():
    
    return render_template('index.html')

@app.route('/uploader', methods = ['GET', 'POST'])
def upload_file():
   if request.method == 'POST':
      fl = request.files['file']
      filenmae = secure_filename(fl.filename)
      fl.save(os.path.join(app.config['location'], filenmae))
      
      rules= yara.compile('/home/harishankar/v2/malware_index.yar')

      entries = Path('/home/harishankar/v2/scanfile/')
      for entry in entries.iterdir():
           
      
        #with open(entry.name) as f:
          # matches = rules.match(data=f.read())



       matches = rules.match('/home/harishankar/v2/scanfile/{{entery.name}}')
      
      return f'{matches}'


#@app.route('/<usr>')
#def files(usr):
#   return 'file got '


if __name__ == "__main__":
    app.run(debug=True)