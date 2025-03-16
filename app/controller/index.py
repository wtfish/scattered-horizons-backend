from flask import render_template

def test():
    return render_template('test.html')
def index():
    return "Auth Server is running"