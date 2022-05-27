from flask import Flask, render_template, request, redirect, session
import sqlite3
from sqlite3 import Error
import re
from flask_bcrypt import Bcrypt
from datetime import datetime
import smtplib, ssl
from smtplib import SMTPAuthenticationError
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
bcrypt = Bcrypt(app)
DATABASE = "dictionary.db"
app.secret_key = "1234566778guygft698t7843y7349gtewg45"


def create_connection(db_file):
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)
    return None


@app.route('/')
def render_homepage():
    return render_template('home.html', logged_in=is_logged_in())


@app.route('/dictionary')
def render_menu_page():
    # connect to the database
    con = create_connection(DATABASE)

    # select the things you want from your table(s)
    query = "SELECT maori, description, level, image, user_id, id FROM product"

    cur = con.cursor()  # You need this lin next
    cur.execute(query)  # this line executes the query
    translation_list = cur.fetchall()  # puts the results into a lst usable in python
    con.close()
    return render_template('menu.html', items=translation_list, logged_in=is_logged_in())


@app.route('/contact')
def render_contact():
    return render_template('contact.html', logged_in=is_logged_in())


@app.route('/login', methods=['POST', 'GET'])
def render_login_page():
    if is_logged_in():
        return redirect('/')

    if request.method == 'POST':
        email = request.form.get('email').title().lower()
        password = request.form.get('password')

        query = """SELECT id, fname, password FROM user WHERE email=?"""
        con = create_connection(DATABASE)
        cur = con.cursor()
        cur.execute(query, (email,))
        user_data = cur.fetchall()
        con.close()

        # if given the email is not in the database this will raise an error
        # would be better to find out how to see if the query return an empty list

        try:
            customer_id = user_data[0][0]
            first_name = user_data[0][1]
            db_password = user_data[0][2]
            print(customer_id, first_name)
        except IndexError:
            return redirect("/login?error=Email+invalid+or+password+incorrect")

        # check if the password is incorrect for that email address

        if not bcrypt.check_password_hash(db_password, password):
            return redirect(request.referrer + "?error+Email+invalid+or+password+incorrect")

        session['email'] = email
        session['userid'] = customer_id
        session['first_name'] = first_name
        print(session)
        return redirect('/')
    return render_template('login.html', logged_in=is_logged_in())


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
        re1 = re.compile(r"[<>/{}[\]~`.?;:-=_+)(*&^%$#@!,]");

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

        query = "INSERT INTO user (id, fname, lname, email, password) VALUES (?, ?, ?, ?, ?)"
        cur = con.cursor()  # you need this line next

        try:
            cur.execute(query, (fname, lname, email, hashed_password))  # this line executes the query
        except sqlite3.IntegrityError:
            return redirect('/signup?error=Email+is+already+used')

        con.commit()
        con.close()

        return redirect("/login")

    # if the request was a GET request
    error = request.args.get('error')
    if error is None:
        error = ""

    return render_template('signup.html', error=error, logged_in=is_logged_in())


@app.route('/logout')
def logout():
    if not is_logged_in():
        return redirect('/')

    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    return redirect('/?message=See+you+next+time!')


def is_logged_in():
    if session.get('email') is None:
        print('not logged in')
        return False
    else:
        print('logged in')
        return True


def send_confirmation(order_info):
    print(order_info)
    email = session['email']
    firstname = session['firstname']
    SSL_PORT = 465  # For SSL

    sender_email = input("Gmail address: ").strip()
    sender_password = input("Gmail password: ").strip()
    table = "<table>\n<tr><th>Name</th><th>Quantity</th><th>Price</th><th>Order total</th></tr>\n"
    total = 0
    for product in order_info:
        name = product[2]
        quantity = product[1]
        price = product[3]
        subtotal = product[3] * product[1]
        total += subtotal
        table += "<tr><td>{}</td><td>{}</td><td>{:.2f}</td><td>{:.2f}</td></tr>\n".format(name, quantity, price,
                                                                                          subtotal)
    table += "<tr><td></td><td></td><td>Total:</td><td>{:.2f}</td></tr>\n</table>".format(total)
    print(table)
    print(total)
    html_text = """<p>Hello {}.</p>
   <p>Thank you for shopping at smile cafe. Your order summary:</p>"
   {}
   <p>Thank you, <br>The staff at smile cafe.</p>""".format(firstname, table)
    print(html_text)

    context = ssl.create_default_context()
    message = MIMEMultipart("alternative")
    message["Subject"] = "Your order with smile"

    message["From"] = "smile cafe"
    message["To"] = email

    html_content = MIMEText(html_text, "html")
    message.attach(html_content)
    with smtplib.SMTP_SSL("smtp.gmail.com", SSL_PORT, context=context) as server:
        try:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, message.as_string())
        except SMTPAuthenticationError as e:
            print(e)


app.run(host='0.0.0.0', debug=True)


