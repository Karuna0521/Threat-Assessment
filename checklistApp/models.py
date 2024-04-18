from django.db import models
from django.contrib.auth.models import AbstractUser

STATUS_CHOICES = (
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    )

# AbstractUser
class User(AbstractUser):
    # first_name = models.CharField(blank=False, max_length=50)
    # last_name = models.CharField(blank=False, max_length=50)
    full_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    role = models.CharField(blank=False, max_length=20)
    password = models.CharField(max_length=25, blank=False)
    confirm_password = models.CharField(max_length=25, blank=False)
    team = models.CharField(max_length=25, blank=False)
    specialization = models.CharField(max_length=25, blank=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='inactive')
    updated_date = models.DateField(blank=False)
    first_name = None
    last_name = None
    REQUIRED_FIELDS = []
    USERNAME_FIELD = 'email' #to use the email as the only unique identifier.
    def __str__(self):
        return self.username

class ChecklistAppHome(models.Model):
    full_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    role = models.CharField(blank=False, max_length=20)
    password = models.CharField(max_length=25, blank=False)
    confirm_password = models.CharField(max_length=25, blank=False)
    team = models.CharField(max_length=25, blank=False)
    specialization = models.CharField(max_length=25, blank=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='inactive')
    updated_date = models.DateField(blank=False)

    class Meta:
        managed = False
        db_table = 'checklistApp_user'

class Captcha(models.Model):
    key = models.CharField(max_length=255)
    captcha_string = models.CharField(max_length=255)
    count = models.IntegerField(blank=True)


class AudRevMapping(models.Model):
    rev_id = models.IntegerField()
    aud_id = models.IntegerField()
    class Meta:
        unique_together = ('rev_id', 'aud_id')

class ChecklistType(models.Model):
    checklist_title = models.CharField(max_length=255,unique=True)
    subcategories = models.JSONField(max_length=500, unique=True, default=list, encoder=None)
    questions = models.JSONField(max_length=500, unique=True, default=list, encoder=None)


class ChecklistData(models.Model):
    checklist_title = models.CharField(max_length=255, unique=True)
    subcategories = models.JSONField()

class QuestionData(models.Model):
    checklist = models.ForeignKey(ChecklistData,related_name='questions', on_delete=models.CASCADE)
    subcategory = models.CharField(max_length=200)
    question_text = models.CharField(max_length=500)

class Options(models.Model):
    option_text = models.CharField(max_length=25, blank=False) 

class AppInfo(models.Model):
    STATUS_CHOICES = [
        ('assigned_to_rev', 'Assigned to Reviewer'),
        ('assigned_to_aud', 'Assigned to Auditor'),
        ('submitted_to_rev', 'Submitted to Reviewer'),
        ('submitted_to_admin', 'Submitted to Admin'),
        ('inprogress', 'In Progress'),
        ('completed', 'Completed'),
        ('hold', 'Hold'),
    ]
    app_name = models.CharField(max_length=100)
    checklist_id = models.IntegerField()
    reviewer_id = models.IntegerField()
    auditor_id = models.IntegerField()
    status = models.CharField(max_length=25, choices=STATUS_CHOICES, default='assigned_to_rev')
    timeline = models.JSONField(max_length=500, default=list, encoder=None)
    created_date = models.DateField(auto_now_add=True)
    reviewer_assigned_date = models.DateField()
    auditor_assigned_date = models.DateField()
    updated_date = models.DateField(auto_now=True)

class AppDetail(models.Model):
    # checklist_id = models.IntegerField()
    app_info =  models.ForeignKey(AppInfo, related_name='app_detail', on_delete=models.CASCADE)
    unique_field = models.CharField(max_length=250)
    subcategory_weightage = models.JSONField(max_length=500, default=dict, encoder=None)
    category_wise_rating = models.JSONField(max_length=500, default=dict ,encoder=None)
    option_wise_count = models.JSONField(max_length=500, default=dict ,encoder=None)
    risk_rating = models.FloatField()
    remarks = models.JSONField(max_length=500, default=list, encoder=None)

class AppField(models.Model):
    app_detail =  models.ForeignKey(AppDetail, related_name='app_fields', on_delete=models.CASCADE)
    key = models.CharField(max_length=250, blank=False)
    value = models.CharField(max_length=250, blank=False)

class AnswerData(models.Model):
    app_detail =  models.ForeignKey(AppDetail, related_name='answers', on_delete=models.CASCADE)
    subcategory = models.CharField(max_length=250, blank=False)
    question_text = models.CharField(max_length=550, blank=False)
    answer_text = models.CharField(max_length=250, blank=False)
    POCs = models.JSONField(max_length=250, default=list, encoder=None)
