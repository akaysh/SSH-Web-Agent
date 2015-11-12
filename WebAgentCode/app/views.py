import commands, pdb
from flask import render_template, request
from app import app


@app.route('/')
@app.route('/index')
def index():
    return "Hello, world!"


@app.route('/webagent')
def webagent():
    return render_template('webagent.html')


# @app.route('/success', methods=['POST'])
# def success():
# 	f = open('static/text/erdata.txt', 'w')
# 	f.write(request.form['test'])
# 	return 'Success!' + request.form['test']

@app.route('/api/sys', methods=['POST'])
def sys():
	cmd = request.form['command']
	args = request.form['arguments']
	return commands.getoutput(cmd+' '+args)