from django.urls import path
from checklistApp import views
from .views import *
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path('register', UserRegistrationView.as_view()),
    path('register/<int:id>', UserRegistrationView.as_view()),
    path('userdata', UserApi.as_view()),
    path('login', UserLogin.as_view()),
    path('captchaString', CaptchaStringAPIView.as_view()),
    path('auditors', AuditorData.as_view()),
    path('logout', UserLogout.as_view()),
    path('options', OptionsView.as_view()),
    path('app_info', AppInfoView.as_view()),
    path('user_appinfo', UserAppInfoApiview.as_view()),
    path('token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('checklist', ChecklistDataCreateView.as_view()),
    path('checklist_detail/<int:id>', ChecklistDataDetailView.as_view()),
    path('question',QuestionDataCreateView.as_view()),
    path('question_detail/<int:id>',QuestionDataDetailView.as_view()),
    path('excelupload', ExcelFileUploadView.as_view()),
    path('apps', AppInfoViewForAdmin.as_view()),
    path('apps/<int:id>', AppInfoViewForAdmin.as_view()),
    path('rev_apps/<int:id>', AppInfoViewForReviewer.as_view()),
    # path('get_apps', GetAppInfoView.as_view()),
    path('app_detail', AppDetailView.as_view()),
    path('app_detail/<int:app_info_id>', AppDetailView.as_view()), # For get     
    path('app_field', AppFieldView.as_view()),  
    path('app_field/<int:app_field_id>', AppFieldView.as_view()),
    path('answer', AnswerDataView.as_view()),
    path('get_appinfo', GetAppInfoView.as_view()),
    path('app_count', AppCountView.as_view()),
    path('status_change', StatusChangeView.as_view()),
    path('remark', RemarkView.as_view()),
    path('result', ResultView.as_view()),
]
