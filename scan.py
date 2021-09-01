from flask import Flask, flash, request, redirect, url_for,render_template ,send_from_directory, jsonify
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

      #entries = Path('/home/harishankar/v2/scanfile/')
      entries ='/home/harishankar/v2/scanfile/'
      for entry in os.listdir(entries):
        if os.path.isfile(os.path.join(entries, entry)):
         matches = rules.match(os.path.join(entries, entry))
         

         if (matches):
           #print([i.tags for i in matches])
           nl='\n'
           sta = f'''Rules matched {','.join([f"Rule Name : {i.rule} {nl}Tags {','.join(i.tags)} {nl}{','.join([f'{key} : {value}{nl} ' for key,value in i.meta.items()])} {nl} Strings Matched:{','.join([f'Offset:{j[0]} String Data{j[2]}' for j in i.strings])} {nl}" for i in matches])}'''
           #f'''Rules matched {','.join([f"Rule Name : {i.rule} {nl}Tags {','.join(i.tags)} {nl}{','.join([f'{key} : {value}{nl} ' for key,value in i.meta.items()])} {nl} " for i in matches])}'''
           #f'''File has {','.join([f"Rule Name : {i.rule} Tags: {','.join(i.tags)} meta: {','.join(i.meta)}" for i in matches])}'''
         else:
           sta ="not virus "      

        os.remove(os.path.join(entries, entry))
      #return jsonify({"a":"hs"})   
      return render_template('output.html', outputs=sta )
        


#@app.route('/<usr>') 
#def files(usr):
#return 'file got 

if __name__ == "__main__":
    app.run(debug=True)