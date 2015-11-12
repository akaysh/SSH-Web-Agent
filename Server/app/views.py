import commands, pdb
import webserver
from flask import render_template, request
from app import app

@app.route('/webagent')
def webagent():
    print "debug"
    if webserver.start() == "Success!":
        return render_template('webagent.html')
    else:
        return render_template('error.html')

@app.route('/')
@app.route('/server')
def server():
    return render_template('server.html')

@app.route('/api/sys', methods=['POST'])
def sys():
    cmd = request.form['command']
    args = request.form['arguments']
    return commands.getoutput(cmd+' '+args)