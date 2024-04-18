class AppDetailView(APIView):
    def create_app_feilds(self, id, key, value):
        existingkey = AppField.objects.filter(key=key, app_detail_id=id)
        if len(existingkey) > 0:
            return Response({'status_code':400, 'errors':[], 'message': key +' already Exists.!'}, status=status.HTTP_400_BAD_REQUEST)
        
        data = dict(app_detail_id=id, key=key, value=value)
        serializer = AppFieldSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({'status_code': 200, 'errors': [], 'message': 'App Field created successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'status_code':400, 'errors':serializer.errors}, status=status.HTTP_400_BAD_REQUEST)



    def post(self, request): # Create Key Value for app_field and subcategory weightage
        app_info_id = request.data.get('app_info_id')
        unique_field = request.data.get('unique_field')
        subcategory_weightage = request.data.get('subcategory_weightage')
        app_fields = request.data.get('app_fields')

        # validation for AppInfo Id exists
        app_info = AppInfo.objects.filter(id=app_info_id)
        if len(app_info) == 0:
            return Response({'status_code': 400, 'message': 'Invalid app_info_id provided.'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Validation for Subcategory
        checklist = ChecklistData.objects.filter(id=app_info[0].checklist_id)[0]
        for key,value in subcategory_weightage.items():
            key = str(key).capitalize()
            if key not in checklist.subcategories:
                return Response({'status_code':400, 'message':key +' Subcategory not present in checklist.'},status=status.HTTP_400_BAD_REQUEST)
            if not (0 <= value <=5 ) :
                return Response({'status_code':400, 'message':'Subcategory weightage must be between 0 to 5.'},status=status.HTTP_400_BAD_REQUEST)

        # validation on unique_field
        # Check if unique_field value is present in app_fields
        unique_field_present = False
        for field in app_fields:
            if field["key"] == unique_field:
                unique_field_present = True
                break

        if unique_field_present == False:
            return Response({'status_code':400, 'message':'Unique Field is not present in App Fields.'},status=status.HTTP_400_BAD_REQUEST)

        # To avoid Multiple details of same application
        existing_app_detail = AppDetail.objects.filter(app_info_id=app_info_id)
        if len(existing_app_detail) > 0:
            return Response({'status_code':400, 'message':'App Details already exists for this application'},status=status.HTTP_400_BAD_REQUEST)

        data = dict(app_info_id=app_info_id, unique_field=unique_field, subcategory_weightage=subcategory_weightage)
        serializer = AppDetailSerializer(data=data)
        if serializer.is_valid():
            app_info_id = serializer.validated_data.get('app_info_id')
            unique_field = serializer.validated_data.get('unique_field')   
            subcategory_weightage = serializer.validated_data.get('subcategory_weightage')   
            created = AppDetail.objects.create(
                    app_info_id=app_info_id,
                    unique_field=unique_field,
                    subcategory_weightage=subcategory_weightage
            )
            print("App Details--->", created.id)
            if created:
                for field in app_fields:
                    response = self.create_app_feilds(created.id, field['key'], field['value'])
                    # Check if response indicates an error, and if so, return it immediately
                    if response.status_code != status.HTTP_200_OK:
                        return response
                application = AppInfo.objects.get(id=app_info_id)
                application.status = "inprogress"
                application.save()
                return Response({'status_code':200, 'errors':[],'message':'App Detail Added successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'status_code': 400, 'errors': serializer.errors, 'message': 'Validation errors occurred.'}, status=status.HTTP_400_BAD_REQUEST)

    def get(self,request, app_info_id):# get by app_info_id
        app_detail = AppDetail.objects.filter(app_info_id=app_info_id)
        if len(app_detail) > 0:
            serializer = AppDetailSerializer(app_detail[0])
            return Response({'status_code':200, 'payload': serializer.data}, status=status.HTTP_200_OK)
        return Response({'status_code': 400, 'errors': [], 'message': 'Invalid App Info Id.'}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, app_info_id): # Delete app info by app_info_id
        app_detail = AppDetail.objects.filter(app_info_id=app_info_id)
        if len(app_detail) > 0:
            app_detail[0].delete()
            return Response({'status_code':200, 'message':'App Detail Deleted Successfully'}, status=status.HTTP_200_OK)
        return Response({'status_code': 400, 'errors': [], 'message': 'Invalid App Info Id.'}, status=status.HTTP_400_BAD_REQUEST)

    def patch(self,request,app_info_id): # To edit unique_feild, subcategory_weightage
        unique_field = request.data.get('unique_field')
        subcategory_weightage = request.data.get('subcategory_weightage')
        app_info = AppInfo.objects.filter(id=app_info_id)
        if len(app_info) == 0:
            return Response({'status_code': 400, 'message': 'Invalid app_info_id provided.'}, status=status.HTTP_400_BAD_REQUEST)

        checklist = ChecklistData.objects.filter(id=app_info[0].checklist_id)[0]
        for key,value in subcategory_weightage.items():
            key = str(key).capitalize()
            if key not in checklist.subcategories:
                return Response({'status_code':400, 'message':str(key) + ' Subcategory does not exists in Checklist'},status=status.HTTP_400_BAD_REQUEST)
            if not (0 <= value <=5 ) :
                return Response({'status_code':400, 'message':'Subcategory weightage must be between 0 to 5.'},status=status.HTTP_400_BAD_REQUEST)

        app_detail = AppDetail.objects.filter(app_info_id=app_info_id)
        app_fields = AppField.objects.filter(app_detail_id=app_detail[0].id, key=unique_field)
        if len(app_fields) == 0:
            return Response({'status_code':400, 'message':'Unique Field is not present in App Fields.'},status=status.HTTP_400_BAD_REQUEST)
        print('sub--->',subcategory_weightage)
        data = dict(unique_field=unique_field, subcategory_weightage=subcategory_weightage)
        
        serializer = AppDetailSerializer(app_detail[0], data=data, partial=True)
        if serializer.is_valid():
           print('valid-->',serializer.validated_data)
           return Response({'status_code':200, 'errors':[],'message':'App Detail Edited successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'status_code': 400, 'errors': serializer.errors, 'message': 'Validation errors occurred.'}, status=status.HTTP_400_BAD_REQUEST)