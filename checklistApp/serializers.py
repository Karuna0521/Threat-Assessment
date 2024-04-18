from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from checklistApp.models import *
import re

class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
            required=True,
            validators=[UniqueValidator(queryset=User.objects.all())]
            )
    password = serializers.CharField(max_length=25)
    confirm_password = serializers.CharField(style={'input_type':'password'}, write_only=True, required=True)

    class Meta:
        model = User    
        fields = [ 'id', 'full_name', 'email', 'password','confirm_password', 'role', 'team','status','specialization']
        extra_kwargs = {
            'full_name': {'required': True},
            # 'last_name': {'required': True},
            'password': {'write_only': True}, 
            }
    # Validating Password and Confirm Password while Registration
    def validate_password(self, password):
        if not re.match(r'^(?=.*\d)(?=.*[A-Z])(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$', password):
            raise serializers.ValidationError("Password must be more than 8 characters with at least one symbol, one uppercase letter, and digits.")
        confirm_password = self.initial_data.get('confirm_password')

        if password != confirm_password:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return password  

    def validate_full_name(self, value):
        if not re.match(r'^[A-Za-z ]+$', value):
            raise serializers.ValidationError("First name must contain only alphabets.")
        return value
    # def validate_last_name(self, value):
    #     if not re.match(r'^[A-Za-z]+$', value):
    #         raise serializers.ValidationError("Last name must contain only alphabets and no spaces.")
    #     return value
    def validate_role(self, value):
        if not re.match(r'^[A-Za-z]+$', value):
            raise serializers.ValidationError("Role must contain only alphabets and no spaces.")
        return value
    def validate_team(self, value):
        if not re.match(r'^[A-Za-z]+$', value):
            raise serializers.ValidationError("Team must contain only alphabets and no spaces.")
        return value
    def validate_specialization(self, value):
        if not re.match(r'^[A-Za-z]+$', value):
            raise serializers.ValidationError("Specialization must contain only alphabets and no spaces.")
        return value 
    
    def create(self, validated_data):
        user = User(
            full_name=validated_data['full_name'],
            # last_name=validated_data['last_name'],
            username=validated_data['email'],
            email=validated_data['email'],
            role=validated_data['role'],
            team=validated_data['team'],
            specialization=validated_data['specialization'],
            # updated_date=validated_data['updated_date'],
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['role','status']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True, max_length=255)
    password = serializers.CharField(required=True, max_length=100)
    class Meta:
        model = User
        fields = [ "email", "password" ]   
    
class CaptchaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Captcha
        fields = '__all__'

class Captcha_count_ser(serializers.ModelSerializer):

    class Meta:
        model = Captcha
        fields = ["count"]

class AudRevMapSerializer(serializers.ModelSerializer):
    rev_id = serializers.IntegerField()
    aud_id = serializers.IntegerField()
    class Meta:
        model = AudRevMapping
        fields = '__all__'

class ChecklistTypeSerializer(serializers.ModelSerializer):
    checklist_title = serializers.CharField()
    subcategories = serializers.ListField(child=serializers.CharField())
    questions = serializers.JSONField(required=False)

    def validate_checklist_title(self, value):
        if not re.match(r'^[A-Za-z ]+$', value):
            raise serializers.ValidationError("Checklist Title must contain only alphabets.")
        return value
    def validate_subcategories(self, value):
        for subcategory in value:
            if not re.match(r'^[A-Za-z ]+$', subcategory):
                raise serializers.ValidationError("Subcategories must contain only alphabets.")
        if len(set(value)) != len(value):
            raise serializers.ValidationError("Subcategories must be unique within a checklist.")  
        return value
    
    class Meta:
        model=ChecklistType
        # fields = ['checklist_title','subcategories']
        # exclude=['questions']
        # fields=['id','checklist_title','subcategories']
        fields = '__all__'

class QuestionDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = QuestionData
        fields = ['id', 'checklist_id', 'subcategory', 'question_text']   

class ChecklistDataSerializer(serializers.ModelSerializer):
    questions = QuestionDataSerializer(many=True, read_only=True)
    def validate_checklist_title(self, value):
        if not re.match(r'^[A-Za-z ]+$', value):
            raise serializers.ValidationError("Checklist Title must contain only alphabets.")
        return value
    def validate_subcategories(self, value):
        for subcategory in value:
            if not re.match(r'^[A-Za-z ]+$', subcategory):
                raise serializers.ValidationError("Subcategories must contain only alphabets.")
        if len(set(value)) != len(value):
            raise serializers.ValidationError("Subcategories must be unique within a checklist.")  
        return value
    class Meta:
        model = ChecklistData
        fields = ['id', 'checklist_title', 'subcategories', 'questions']

class AppFieldSerializer(serializers.ModelSerializer):
    app_detail_id = serializers.IntegerField(required=False)
    class Meta:
        model = AppField
        fields = ['id', 'app_detail_id', 'key', 'value']


class AnswerDataSerializer(serializers.ModelSerializer):
    app_detail_id = serializers.IntegerField(required=False)
    POCs = serializers.CharField(required=False)
    class Meta:
        model = AnswerData
        fields = ['id', 'app_detail_id','subcategory', 'question_text', 'answer_text', 'POCs']

class AppDetailSerializer(serializers.ModelSerializer):
    app_info_id = serializers.IntegerField(required=False)
    subcategory_weightage = serializers.JSONField(required=False)
    answers = AnswerDataSerializer(many=True, read_only=True)
    app_fields = AppFieldSerializer(many=True, read_only=True)
    category_wise_rating = serializers.JSONField(required=False)
    option_wise_count = serializers.JSONField(required=False)
    risk_rating = serializers.FloatField(required=False)
    remarks = serializers.JSONField(required=False)
    class Meta:
        model = AppDetail
        fields = ['id', 'app_info_id','answers','app_fields', 'unique_field', 'subcategory_weightage', 'category_wise_rating', 'option_wise_count', 'risk_rating', 'remarks']

class AppInfoSerializer(serializers.ModelSerializer):
    app_detail = AppDetailSerializer(many=True, read_only=True)
    auditor_id = serializers.IntegerField(required=False)
    auditor_assigned_date = serializers.DateField(required=False)
    def validate_app_name(self,value):
        if not re.match(r'^[A-Za-z ]+$', value):
            raise serializers.ValidationError("App name must contain only alphabets.")
        return value
   
    class Meta:
        model = AppInfo
        fields = ['id','app_name','checklist_id','app_detail','reviewer_id','status','timeline','created_date','auditor_assigned_date','reviewer_assigned_date','auditor_id','updated_date']
       # exclude = ['auditor_assigned_date']


class ExcelUploadSerializer(serializers.ModelSerializer):
    file = serializers.FileField()

    def validate_excel_file(self, value):
        # Check file extension
        if not value.name.endswith('.xlsx'):
            raise serializers.ValidationError("Invalid file format. Please upload a .xlsx file")

        # Check file size
        max_size = 5 * 1024 * 1024  # 5MB
        if value.size > max_size:
            raise serializers.ValidationError("File size exceeds the limit of 5MB")

        # You can add more validations here if needed
        return value


class OptionsSerializer(serializers.ModelSerializer):
    option_text = serializers.CharField()
    def validate_option_text(self, value):
        if not re.match(r'^[A-Za-z ]+$', value):
            raise serializers.ValidationError("Options must contain only alphabets.")
        return value
    class Meta:
        model = Options
        fields = '__all__'