MANIFEST_DESC = {
    'a_clear_text': {
        'title': ('已为应用程序启用明文通信'
                  '<br>[android:usesCleartextTraffic=true]'),
        'level': 'high',
        'description': ('该应用程序打算使用明文网络流量,例如明文HTTP、FTP堆栈、DownloadManager和MediaPlayer。'
                        '默认针对API级别27或更低的应用程序为<True>。以API级别28或更高为目标的应用程序默认为<False>'
                        '避免使用明文的关键原因就是缺乏机密性真实性和防篡改保护。'
                        '网络攻击者可以窃听传输的信息数据，并在不被检测的情况下对其进行修改'),
        'name': ('已为应用程序启用明文通信'
                 '[android:usesCleartextTraffic=true]'),
    },
    'a_debuggable': {
        'title': '为App启用调试<br>[android:debuggable=true]',
        'level': 'high',
        'description': ("""
        调试是在应用程序上打开的,这使得
        反向工程师更容易将调试器连接到
        它。这允许转储堆栈跟踪和访问调试助手类
        """),
        'name': '为App启用调试 [android:debuggable=true]',
    },
    'a_allowbackup': {
        'title': ('应用数据可以备份'
                  '<br>[android:allowBackup=true]'),
        'level': 'medium',
        'description': ("""
        此标志允许任何人备份您的应用程序数据。
        它允许已启用USB的用户进行调试以复制应用程序数据设备。
        """),
        'name': '应用数据可以备份 [android:allowBackup=true]',
    },
    'a_allowbackup_miss': {
        'title': ('应用数据可以备份<br>[android:allowBackup]'
                  ' flag is missing.'),
        'level': 'medium',
        'description': ("""
        flag [android:allowBackup]应该设置为false。默认情况下，它被设置为true并允许任何人这样做
        通过adb备份您的应用程序数据。它允许用户
        谁已启用USB调试复制应用程序
        数据从设备中删除。
        """),
        'name': ('应用数据可以备份 [android:allowBackup] flag'
                 ' is missing.'),
    },
    'a_testonly': {
        'title': '应用程序处于测试模式 <br>[android:testOnly=true]',
        'level': 'high',
        'description': ("""
        它可能会暴露自身之外的功能或数据，
        这会造成一个安全漏洞。
        """),
        'name': '应用程序处于测试模式 [android:testOnly=true]',
    },
    'a_taskaffinity': {
        'title': '给Activity设置了TaskAffinity </br>(%s)',
        'level': 'high',
        'description': ('If taskAffinity is set, then other application'
                        ' could read the Intents sent to Activities '
                        'belonging to another task. Always use the default'
                        ' setting keeping the affinity as the package name'
                        ' in order to prevent sensitive information inside'
                        ' sent or received Intents from being read by '
                        'another application.'),
        'name': 'TaskAffinity is set for Activity',
    },
    'a_launchmode': {
        'title': 'Activity (%s) 的启动模式不符合标准',
        'level': 'high',
        'description': ("""
        一个活动不应该拥有启动模式属性设置为singleTask/singleInstance
        它变成了根活动，并且它是可能读取其他应用程序的内容。
        所以它需要使用“standard”启动模式属性时敏感信息包含在意图中。
        """),
        'name': 'Activity 的启动模式不符合标准',
    },
    'a_prot_normal': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但权限保护级别应该被检查。'
                  '</br>%s <br>[android:exported=true]'),
        'level': 'high',
        'description': ('%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a '
                        'permission. However, the protection level of the'
                        '  permission is set to normal. This means that a '
                        'malicious application can request and obtain'
                        ' the permission and interact with the component.'
                        ' If it was set to signature, only applications '
                        'signed with the same certificate could obtain '
                        'the permission.'),
        'name': ('受权限保护，但权限保护级别应该被检查。[android:exported=true]'),
    },
    'a_prot_danger': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked.'
                  '</br>%s <br>[android:exported=true]'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a'
                        ' permission. However, the protection level of the'
                        ' permission is set to dangerous. This means that a'
                        ' malicious application can request and obtain the'
                        ' permission and interact with the component. If it'
                        ' was set to signature, only applications signed with'
                        ' the same certificate could obtain the permission.'),
        'name': ('is Protected by a permission, but the protection level of'
                 ' the permission should be checked.[android:exported=true]'),
    },
    'a_prot_unknown': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked.'
                  '</br>%s <br>[android:exported=true]'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a '
                        'permission which is not defined in the analysed '
                        'application. As a result, the protection level of the'
                        ' permission should be checked where it is defined. If'
                        ' it is set to normal or dangerous, a malicious '
                        'application can request and obtain the permission and'
                        ' interact with the component. If it is set to '
                        'signature, only applications signed with the same '
                        'certificate can obtain the permission.'),
        'name': ('is Protected by a permission, but the protection level '
                 'of the permission should be '
                 'checked.[android:exported=true]'),
    },
    'a_prot_normal_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the '
                  'permission should be checked.</br>%s <br>'
                  '[android:exported=true]'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device.  It is protected by a '
                        'permission at the application level. However, the'
                        ' protection level of the permission is set to normal.'
                        ' This means that a malicious application can request '
                        'and obtain the permission and interact with the '
                        'component. If it was set to signature, only '
                        'applications signed with the same certificate '
                        'could obtain the permission.'),
        'name': ('is Protected by a permission at the application level,'
                 ' but the protection level of the permission should be '
                 'checked.[android:exported=true]'),
    },
    'a_prot_danger_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the '
                  'permission should be checked.'
                  '</br>%s <br>[android:exported=true]'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a '
                        'permission at the application level. However, the '
                        'protection level of the permission is set to '
                        'dangerous. This means that a malicious application '
                        'can request and obtain the permission and interact '
                        'with the component. If it was set to signature, '
                        'only applications signed with the same certificate'
                        ' could obtain the permission.'),
        'name': ('is Protected by a permission at the application level, but'
                 ' the protection level of the permission should be '
                 'checked.[android:exported=true]'),
    },
    'a_prot_unknown_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission'
                  ' at the application, but the protection level of the '
                  'permission should be checked.'
                  '</br>%s <br>[android:exported=true]'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps on '
                        'the device therefore leaving it accessible to any'
                        ' other application on the device. It is protected'
                        ' by a permission at the application level which is'
                        ' not defined in the analysed application. As a'
                        ' result, the protection level of the permission'
                        ' should be checked where it is defined. If it is'
                        ' set to normal or dangerous, a malicious application'
                        ' can request and obtain the permission and interact'
                        ' with the component. If it is set to signature, only'
                        ' applications signed with the same certificate can'
                        ' obtain the permission.'),
        'name': ('is Protected by a permission at the application, but the'
                 ' protection level of the permission should be checked.'
                 '[android:exported=true]'),
    },
    'a_not_protected': {
        'title': ('<strong>%s</strong> (%s) is not Protected.'
                  ' <br>[android:exported=true]'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device.'),
        'name': 'is not Protected. [android:exported=true]',
    },
    'a_not_protected_filter': {
        'title': ('<strong>%s</strong> (%s) is not Protected.<br>'
                  'An intent-filter exists.'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other '
                        'application on the device. The presence of '
                        'intent-filter indicates that the %s'
                        ' is explicitly exported.'),
        'name': 'is not Protected.An intent-filter exists.',
    },
    'c_not_protected': {
        'title': ('<strong>%s</strong> (%s) is not Protected. <br>'
                  '[[Content Provider, targetSdkVersion < 17]'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps'
                        ' on the device therefore leaving it accessible '
                        'to any other application on the device. It is '
                        'a Content Provider that targets an API level '
                        'under 17, which makes it exported by default,'
                        ' regardless of the API level of the system '
                        'that the application runs on.'),
        'name': 'is not Protected.[[Content Provider, targetSdkVersion < 17]',
    },
    'c_not_protected2': {
        'title': ('<strong>%s</strong> (%s) would not be Protected if the'
                  ' application ran on a device where the the API level was'
                  ' less than 17. <br>[Content Provider, '
                  'targetSdkVersion >= 17]'),
        'level': 'high',
        'description': ('The Content Provider(%s %s) would be exported if the'
                        ' application ran on a device where the the API level '
                        'was less than 17. In that situation, it would be '
                        'shared with other apps on the device therefore '
                        'leaving it accessible to any other application '
                        'on the device.'),
        'name': ('would not be Protected if the application ran on a device'
                 ' where the the API level was less than 17.[Content Provider,'
                 ' targetSdkVersion >= 17]'),
    },
    'c_prot_normal': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked.'
                  '</br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a '
                        'permission. However, the protection level of the'
                        ' permission is set to normal. This means that a '
                        'malicious application can request and obtain '
                        'the permission and interact with the component. '
                        'If it was set to signature, only applications signed '
                        'with the same certificate could obtain '
                        'the permission.'),
        'name': ('is Protected by a permission, but the protection level'
                 ' of the permission should be checked.[Content Provider,'
                 ' targetSdkVersion < 17]'),
    },
    'c_prot_danger': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, '
                  'but the protection level of the permission should be '
                  'checked.</br>%s <br>[Content Provider, '
                  'targetSdkVersion < 17]'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a '
                        'permission. However, the protection level of the '
                        'permission is set to dangerous. This means that a '
                        'malicious application can request and obtain the '
                        'permission and interact with the component. If it'
                        ' was set to signature, only applications signed with'
                        ' the same certificate could obtain '
                        'the permission.'),
        'name': ('is Protected by a permission, but the protection level of '
                 'the permission should be checked.[Content Provider, '
                 'targetSdkVersion < 17]'),
    },
    'c_prot_unknown': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked.'
                  '</br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps on the '
                        'device therefore leaving it accessible to any other '
                        'application on the device. It is protected by a '
                        'permission which is not defined in the analysed '
                        'application. As a result, the protection level of the'
                        ' permission should be checked where it is defined. If'
                        ' it is set to normal or dangerous, a malicious '
                        'application can request and obtain the permission and'
                        ' interact with the component. If it is set to '
                        'signature, only applications signed with the same '
                        'certificate can obtain the permission.'),
        'name': ('is Protected by a permission, but the protection level of'
                 ' the permission should be checked.[Content Provider,'
                 ' targetSdkVersion < 17]'),
    },
    'c_prot_normal_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the'
                  ' permission should be checked.'
                  '</br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a'
                        ' permission at the application level. However, the'
                        ' protection level of the permission is set to normal.'
                        ' This means that a malicious application can request'
                        ' and obtain the permission and interact with the'
                        ' component. If it was set to signature, only '
                        'applications signed with the same certificate could'
                        ' obtain the permission.'),
        'name': ('is Protected by a permission at the application level, but'
                 ' the protection level of the permission should be checked.'
                 '[Content Provider, targetSdkVersion < 17]'),
    },
    'c_prot_danger_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at '
                  'the application level, but the protection level of the '
                  'permission should be checked.'
                  '</br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a '
                        'permission at the application level. However, the '
                        'protection level of the permission is set to '
                        'dangerous. This means that a malicious application'
                        ' can request and obtain the permission and interact'
                        ' with the component. If it was set to signature, '
                        'only applications signed with the same certificate'
                        ' could obtain the permission.'),
        'name': ('is Protected by a permission at the application level, but'
                 ' the protection level of the permission should be checked.'
                 '[Content Provider, targetSdkVersion < 17]'),
    },
    'c_prot_unknown_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' application level, but the protection level of the '
                  'permission should be checked.</br>%s '
                  '<br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'high',
        'description': ('A%s %s is found to be shared with other apps on the'
                        ' device therefore leaving it accessible to any other'
                        ' application on the device. It is protected by a '
                        'permission at application level which is not defined'
                        ' in the analysed application. As a result, the '
                        'protection level of the permission should be checked'
                        ' where it is defined. If it is set to normal or '
                        'dangerous, a malicious application can request and'
                        ' obtain the permission and interact with the '
                        'component. If it is set to signature, only '
                        'applications signed with the same certificate '
                        'can obtain the permission.'),
        'name': ('is Protected by a permission at application level, but'
                 ' the protection level of the permission should be checked.'
                 '[Content Provider, targetSdkVersion < 17]'),
    },
    'c_prot_normal_new': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, '
                  'but the protection level of the permission should be '
                  'checked if the application runs on a device where the '
                  'the API level is less than 17'
                  '</br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'high',
        'description': ('The Content Provider (%s) would be exported if the'
                        ' application ran on a device where the the API level'
                        ' was less than 17. In that situation, it would still'
                        ' be protected by a permission. However, the '
                        'protection level of the permission is set to normal. '
                        'This means that a malicious application could request'
                        ' and obtain the permission and interact with the'
                        ' component. If it was set to signature, only'
                        ' applications signed with the same certificate '
                        'could obtain the permission.'),
        'name': ('is Protected by a permission, but the protection level of'
                 ' the permission should be checked if the application runs '
                 'on a device where the the API level is less than 17 '
                 '[Content Provider, targetSdkVersion >= 17]'),
    },
    'c_prot_danger_new': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission,'
                  ' but the protection level of the permission should be '
                  'checked if the application runs on a device where '
                  'the API level is less than 17.</br>%s <br>'
                  '[Content Provider, targetSdkVersion >= 17]'),
        'level': 'high',
        'description': ('The Content Provider(%s) would be exported if the'
                        ' application ran on a device where the the API level'
                        ' was less than 17. In that situation, it would still'
                        ' be protected by a permission. However, the '
                        'protection level of the permission is set to'
                        ' dangerous. This means that a malicious application'
                        ' could request and obtain the permission and interact'
                        ' with the component. If it was set to signature, only'
                        ' applications signed with the same certificate could'
                        ' obtain the permission.'),
        'name': ('is Protected by a permission, but the protection level of'
                 ' the permission should be checked if the application runs on'
                 ' a device where the the API level is less than 17.'
                 '[Content Provider, targetSdkVersion >= 17]'),
    },
    'c_prot_unknown_new': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission, but'
                  ' the protection level of the permission should be checked'
                  '  if the application runs on a device where the the API '
                  'level is less than 17.</br>%s <br>'
                  '[Content Provider, targetSdkVersion >= 17]'),
        'level': 'high',
        'description': ('The Content Provider(%s) would be exported if the'
                        ' application ran on a device where the the API level'
                        ' was less than 17. In that situation, it would still'
                        ' be protected by a permission which is not defined in'
                        ' the analysed application. As a result, the '
                        'protection level of the permission should be '
                        'checked where it is defined. If it is set to normal'
                        ' or dangerous, a malicious application can request'
                        ' and obtain the permission and interact with the '
                        'component. If it is set to signature, only '
                        'applications signed with the same certificate'
                        ' can obtain the permission.'),
        'name': ('is Protected by a permission, but the protection level of'
                 ' the permission should be checked  if the application runs'
                 ' on a device where the the API level is less than 17.'
                 '[Content Provider, targetSdkVersion >= 17]'),
    },
    'c_prot_normal_new_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the'
                  ' permission should be checked if the application runs on'
                  ' a device where the the API level is less than 17'
                  '</br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'high',
        'description': ('The Content Provider (%s) would be exported if the'
                        ' application ran on a device where the the API '
                        'level was less than 17. In that situation, it'
                        ' would still be protected by a permission. '
                        'However, the protection level of the permission'
                        ' is set to normal. This means that a malicious'
                        ' application could request and obtain the '
                        'permission and interact with the component. '
                        'If it was set to signature, only applications '
                        'signed with the same certificate could obtain'
                        ' the permission.'),
        'name': ('is Protected by a permission at the application level '
                 'should be checked, but the protection level of the '
                 'permission if the application runs on a device where'
                 ' the the API level is less than 17.'
                 '[Content Provider, targetSdkVersion >= 17]'),
    },
    'c_prot_danger_new_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at'
                  ' the application level, but the protection level of the'
                  ' permission should be checked if the application runs on'
                  ' a device where the the API level is less than 17.'
                  '</br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'high',
        'description': ('The Content Provider(%s) would be exported if the'
                        ' application ran on a device where the the API '
                        'level was less than 17. In that situation, it'
                        ' would still be protected by a permission. However,'
                        ' the protection level of the permission is set to'
                        ' dangerous. This means that a malicious application'
                        ' could request and obtain the permission and interact'
                        ' with the component. If it was set to signature, only'
                        ' applications signed with the same certificate could'
                        ' obtain the permission.'),
        'name': ('is Protected by a permission at the application level, but'
                 ' the protection level of the permission should be checked '
                 'if the application runs on a device where the the API level '
                 'is less than 17.[Content Provider, targetSdkVersion >= 17]'),
    },
    'c_prot_unknown_new_appl': {
        'title': ('<strong>%s</strong> (%s) is Protected by a permission at '
                  'the application level, but the protection level of the '
                  'permission should be checked  if the application runs on'
                  ' a device where the the API level is less than 17.'
                  '</br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'high',
        'description': ('The Content Provider(%s) would be exported if the'
                        ' application ran on a device where the the API level'
                        ' was less than 17. In that situation, it would still'
                        ' be protected by a permission which is not defined '
                        'in the analysed application. As a result, the'
                        ' protection level of the permission should be checked'
                        ' where it is defined. If it is set to normal or'
                        ' dangerous, a malicious application can request'
                        ' and obtain the permission and interact with the'
                        ' component. If it is set to signature, only '
                        'applications signed with the same certificate'
                        ' can obtain the permission.'),
        'name': ('is Protected by a permission at the application level,'
                 ' but the protection level of the permission should be'
                 ' checked  if the application runs on a device where the'
                 ' the API level is less than 17.'
                 '[Content Provider, targetSdkVersion >= 17]'),
    },
    'a_improper_provider': {
        'title': 'Improper Content Provider Permissions<br>[%s]',
        'level': 'high',
        'description': ('A content provider permission was set to allows'
                        ' access from any other app on the device. '
                        'Content providers may contain sensitive '
                        'information about an app and therefore '
                        'should not be shared.'),
        'name': 'Improper Content Provider Permissions',
    },
    'a_dailer_code': {
        'title': ('Dailer Code: %s Found'
                  ' <br>[android:scheme="android_secret_code"]'),
        'level': 'high',
        'description': ('A secret code was found in the manifest. These codes,'
                        ' when entered into the dialer grant access to hidden'
                        ' content that may contain sensitive information.'),
        'name': ('Dailer Code: Found '
                 '<br>[android:scheme="android_secret_code"]'),
    },
    'a_sms_receiver_port': {
        'title': 'Data SMS Receiver Set on Port: %s Found<br>[android:port]',
        'level': 'high',
        'description': ('A binary SMS receiver is configured to listen on a'
                        ' port. Binary SMS messages sent to a device are '
                        'processed by the application in whichever way the'
                        ' developer choses. The data in this SMS should be'
                        ' properly validated by the application. Furthermore,'
                        ' the application should assume that the SMS being'
                        ' received is from an untrusted source.'),
        'name': 'Data SMS Receiver Set on Port: Found<br>[android:port]',
    },
    'a_high_intent_priority': {
        'title': 'High Intent Priority (%s)<br>[android:priority]',
        'level': 'medium',
        'description': ('By setting an intent priority higher than another'
                        ' intent, the app effectively overrides '
                        'other requests.'),
        'name': 'High Intent Priority [android:priority]',
    },
    'a_high_action_priority': {
        'title': 'High Action Priority (%s)<br>[android:priority] ',
        'level': 'medium',
        'description': ('By setting an action priority higher than'
                        ' another action, the app effectively '
                        'overrides other requests.'),
        'name': 'High Action Priority [android:priority]',
    },
}
