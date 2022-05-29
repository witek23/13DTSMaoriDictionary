# import external libraries
from flask import Flask, render_template, request, redirect, session
import sqlite3
from sqlite3 import Error
import re
from flask_bcrypt import Bcrypt
from datetime import datetime

app = Flask(__name__)
bcrypt = Bcrypt(app)
DATABASE = "dictionary.db"
app.secret_key = "1234566778guygft698t7843y7349gtewg45"


# this function creates the initial connection with the database
def create_connection(db_file):
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)
    return None


@app.route('/')
def render_homepage():
    return render_template('home.html', all_categories=get_categories(),
                           user_data=user_id_conversion(session.get("user_id")), logged_in=is_logged_in(),
                           modify=edit())


@app.route('/dictionary/<word_id>')
def render_dictionary_page(word_id):
    # connect to the database
    con = create_connection(DATABASE)

    # select the things you want from your table(s)
    query = "SELECT * FROM product WHERE id=?"

    cur = con.cursor()  # You need this lin next
    cur.execute(query, (word_id,))  # this line executes the query
    translation_list = cur.fetchall()  # puts the results into a list usable in python

    query = "SELECT * FROM user WHERE id=?"
    cur = con.cursor()  # You need this lin next
    cur.execute(query, (translation_list[0][7],))  # this line executes the query
    f_user = cur.fetchall()

    con.close()

    return render_template('dictionary.html', logged_in=is_logged_in(),
                           user_data=user_id_conversion(session.get("user_id")), all_categories=get_categories(),
                           modify=edit(), word_user_data=f_user, words_found=translation_list)


@app.route('/category/<cat_id>')
def render_category_page(cat_id):
    # connect to the database
    con = create_connection(DATABASE)

    # select the things you want from your table(s)
    query = "SELECT * FROM categories WHERE id=?"
    cur = con.cursor()
    cur.execute(query, (cat_id,))
    cur_category = cur.fetchall()

    # select the things you want from your table(s)
    query = "SELECT * FROM product WHERE category_id=?"
    cur = con.cursor()  # You need this lin next
    cur.execute(query, (cat_id,))  # this line executes the query

    translation_list = cur.fetchall()  # puts the results into a list usable in python
    con.close()

    return render_template("category.html", logged_in=is_logged_in(),
                           user_data=user_id_conversion(session.get("user_id")), all_categories=get_categories(),
                           modify=edit(),
                           words_found=translation_list, cat_data=cur_category)


@app.route('/login', methods=['POST', 'GET'])
def render_login_page():
    if is_logged_in():
        return redirect('/')

    if request.method == 'POST':
        email = request.form.get('email').title().lower()
        password = request.form.get('password')
        con = create_connection(DATABASE)

        query = """SELECT * FROM user WHERE email=?"""

        cur = con.cursor()
        cur.execute(query, (email,))
        user_data = cur.fetchall()
        con.close()

        # if given the email is not in the database this will raise an error
        # would be better to find out how to see if the query return an empty list

        try:
            user_id = user_data[0][0]
            fname = user_data[0][1]
            lname = user_data[0][2]
            email = user_data[0][3]
            db_password = user_data[0][4]
            modify = user_data[0][5]
        except IndexError:
            return redirect("/login?error=Email+invalid+or+password+incorrect")

        # check if the password is incorrect for that email address

        if not bcrypt.check_password_hash(db_password, password):
            return redirect(request.referrer + "?error+Email+invalid+or+password+incorrect")

        session['userid'] = user_id
        session['fname'] = fname
        session['lname'] = lname
        session['email'] = email
        session['modify'] = modify
        print(session)
        return redirect('/')
    return render_template('login.html', logged_in=is_logged_in(), modify=edit(),
                           user_data=user_id_conversion(session.get("user_id")), all_categories=get_categories())


@app.route('/signup', methods=['POST', 'GET'])
def render_signup_page():
    if is_logged_in():
        return redirect('/')

    if request.method == 'POST':
        print(request.form)
        fname = request.form.get('fname').title().strip()
        lname = request.form.get('lname').title().strip()
        email = request.form.get('email').title().lower()
        password = request.form.get('password')
        password2 = request.form.get('password2')
        can_modify = request.form.get("modify")
        re1 = re.compile(r"[<>/{}[\]~`.?;:-=_+)(*&^%$#@!,]");

        modify = False
        if can_modify:
            modify = True

        if re1.search(fname):
            return redirect('/signup?error=invalid+character/s')

        if re1.search(lname):
            return redirect('/signup?error=invalid+character/s')

        if len(fname) < 2:
            return redirect('/signup?error=First+name+must+be+3+characters+or+more')

        if len(lname) < 3:
            return redirect('/signup?error=Last+name+must+be+3+characters+or+more')

        if password != password2:
            return redirect('/signup?error=Passwords+dont+match')

        if len(password) < 8:
            return redirect('/signup?error=Password+must+be+8+characters+or+more')

        hashed_password = bcrypt.generate_password_hash(password)

        con = create_connection(DATABASE)

        query = "SELECT id FROM user WHERE email=?"
        cur = con.cursor()
        cur.execute(query, (email,))

        query = "INSERT INTO user (id, fname, lname, email, password, modify) VALUES (NULL, ?, ?, ?, ?, ?)"
        cur = con.cursor()  # you need this line next

        try:
            cur.execute(query, (fname, lname, email, hashed_password, modify))  # this line executes the query
        except sqlite3.IntegrityError:
            return redirect('/signup?error=Email+is+already+used')

        con.commit()
        con.close()

        return redirect("/login")

    return render_template('signup.html', user_data=user_id_conversion(session.get("user_id")),
                           logged_in=is_logged_in(), modify=edit(), all_categories=get_categories())


@app.route('/logout')
def logout():
    if not is_logged_in():
        return redirect('/')

    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    return redirect('/?message=See+you+next+time!')


@app.route("/add", methods=["GET", "POST"])
def render_add():
    return render_template("add.html", logged_in=is_logged_in(),
                           user_data=user_id_conversion(session.get("user_id")),
                           modify=edit(), all_categories=get_categories())


def get_categories():
    con = create_connection(DATABASE)
    query = "SELECT id, name FROM categories"
    cur = con.cursor()
    cur.execute(query)
    category_list = cur.fetchall()
    con.close()
    return category_list


def is_logged_in():
    if session.get('email') is None:
        print('not logged in')
        return False
    else:
        print('logged in')
        return True


def user_id_conversion(user_id):
    con = create_connection(DATABASE)
    query = "SELECT * FROM user where id=?"
    cur = con.cursor()
    cur.execute(query, (user_id, ))
    return_name = cur.fetchall()
    print(return_name)
    con.close()
    return return_name


def edit():
    if session.get("modify") == 1:
        print("Is a teacher")
        return True
    else:
        print("is not a teacher")
        return False


app.run(host='0.0.0.0', debug=True)
