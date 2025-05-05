from django.db import models
from django.contrib.auth.models import User


# Create your models here.
class Qualification(models.Model):
    name=models.CharField(max_length=50)
    def __str__(self):
        return self.name
class Subject(models.Model):
    qualification = models.ForeignKey(Qualification, on_delete=models.CASCADE)
    name = models.CharField(max_length=50)

    def __str__(self):
        return self.name


class Career(models.Model):
      INTERESTED_CHOICES = [
        ('Job', 'Job'),
        ('Study', 'Study'),
       
    ]
      qualification=models.ForeignKey(Qualification, on_delete=models.CASCADE)
      subject = models.ForeignKey(Subject, on_delete=models.CASCADE)
      title = models.CharField(max_length=100)
      description = models.TextField()
      maindescription = models.TextField()
      interested = models.CharField(max_length=20, choices=INTERESTED_CHOICES, null=True, blank=True)

class Address(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Change to ForeignKey for multiple addresses
    name = models.CharField(max_length=225)
    address = models.TextField()
    phone = models.CharField(max_length=12)


class ContactMessage(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    message = models.TextField()
    submitted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Message from {self.name} ({self.email})"
    
class UserCareerFilter(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    qualification = models.ForeignKey(Qualification, on_delete=models.SET_NULL, null=True)
    subject = models.ForeignKey(Subject, on_delete=models.SET_NULL, null=True)
    interested = models.CharField(max_length=20, choices=Career.INTERESTED_CHOICES)
    details = models.TextField(blank=True)

    def __str__(self):
        return self.user.username



