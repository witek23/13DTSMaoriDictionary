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



