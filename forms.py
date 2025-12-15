from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, FileField
from wtforms.validators import DataRequired, Email, EqualTo, Length

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ItemForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    status = SelectField('Status', choices=[('Lost','Lost'),('Found','Found')], validators=[DataRequired()])
    category = SelectField('Category', choices=[('Electronics','Electronics'),('Clothes','Clothes'),('Documents','Documents'),('Other','Other')], validators=[DataRequired()])
    contact = StringField('Contact', validators=[DataRequired()])
    image = FileField('Image')
    submit = SubmitField('Submit')

