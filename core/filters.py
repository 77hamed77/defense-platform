# core/filters.py

import django_filters
from django import forms
from .models import Alert

class AlertFilter(django_filters.FilterSet):
    description = django_filters.CharFilter(
        lookup_expr='icontains', 
        label='Description contains'
    )
    start_date = django_filters.DateFilter(
        field_name='timestamp', 
        lookup_expr='gte', 
        label='From Date',
        # نستخدم виджет HTML5 date
        widget=forms.DateInput(attrs={'type': 'date'})
    )
    end_date = django_filters.DateFilter(
        field_name='timestamp', 
        lookup_expr='lte', 
        label='To Date',
        widget=forms.DateInput(attrs={'type': 'date'})
    )

    class Meta:
        model = Alert
        fields = ['source_ip', 'destination_ip', 'severity', 'status', 'source_tool']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        tailwind_classes = "w-full bg-gray-700 border border-gray-600 rounded-md p-2 text-white focus:ring-blue-500 focus:border-blue-500"
        
        # --- هذا هو الجزء الذي تم تصحيحه بشكل نهائي ---
        # نقوم بالتكرار على حقول النموذج (self.form.fields) التي تحتوي على widgets
        for field_name, field in self.form.fields.items():
            field.widget.attrs.update({'class': tailwind_classes})