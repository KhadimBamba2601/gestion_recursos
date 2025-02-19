from flask_wtf import FlaskForm
from wtforms import SelectField, TextAreaField, SubmitField
from wtforms.validators import DataRequired

class LogForm(FlaskForm):
    nivel = SelectField('Nivel', choices=[('info', 'Info'), ('warning', 'Warning'), ('error', 'Error')], validators=[DataRequired()])
    mensaje = TextAreaField('Mensaje', validators=[DataRequired()])
    submit = SubmitField('Crear')