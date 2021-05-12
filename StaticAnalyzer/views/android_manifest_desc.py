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
        'title': '为App启用调试<br>',
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
                  ' 标识缺失。'),
        'level': 'medium',
        'description': ("""
        flag [android:allowBackup]应该设置为false。默认情况下，它被设置为true并允许任何人这样做
        通过adb备份您的应用程序数据。它允许用户启用USB调试复制应用程序数据从设备中删除。
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
        'description': ("""
        如果设置了taskAffinity，则其他应用程序可以读出发送给属于另一个任务的活动的意图。
        总是使用默认值设置将affinity作为包名为了防止里面有敏感信息
        发送或接收意图被读取另一个应用程序。
        """),
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
        'description': ("""
        %s 被发现与其他应用程序共享。因此，任何在设备上其他应用都可以访问它。它被保护着，
        然而，权限设置为normal。这意味着恶意应用程序可以请求和获取允许并与组件交互。
        如果设置为signature，只适用于申请用相同的证书签名可以获得许可。
        """ ),
        'name': ('受权限保护，但权限保护级别应该被检查。[android:exported=true]'),
    },
    'a_prot_danger': {
        'title': ('<strong>%s</strong> (%s) 受权限保护, 但权限保护级别应该被检查。'
                  '</br>%s <br>[android:exported=true]'),
        'level': 'high',
        'description': ("""
        %s被发现与其他应用程序共享.因此，任何在设备上其他应用程序都可以访问它。它被保护着，然而，保护水平权限设置为“危险”。这意味着a
        恶意应用程序可以请求和获取允许并与组件交互。如果它是设置为signature，只有应用程序签名同一证书可以获得该权限。
        """),
        'name': ('受权限保护，但权限保护级别应该被检查。[android:exported=true]'),
    },
    'a_prot_unknown': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但权限保护级别应该被检查。'
                  '</br>%s <br>[android:exported=true]'),
        'level': 'high',
        'description': ("""
        %s被发现与其他应用程序共享.因此，任何在设备上其他应用都可以访问它。它被保护着
        在分析中没有定义的权限应用程序。因此，保护水平应该在定义权限的地方检查权限。如果
        它被设置为正常或危险，恶意申请可以请求并获得权限和与组件交互。如果它被设置为
        signature，只有用相同签名的应用程序证书可以获得权限。
        """),
        'name': ('受权限保护，但权限保护级别应该被检查。[android:exported=true]'),
    },
    'a_prot_normal_appl': {
        'title': ('<strong>%s</strong> (%s) 受application级别权限保护，但权限保护级别应该被检查。</br>%s <br>'
                  '[android:exported=true]'),
        'level': 'high',
        'description': ("""
        %s被发现与其他应用程序共享。因此，任何在设备上其他应用都可以访问它。它被application级别权限保护着，
        然而，权限设置为normal。这意味着恶意应用程序可以请求和获取允许并与组件交互。如果设置为signature，只适用于申请用相同的证书签名可以获得许可。
        """),
        'name': ('受application级别权限保护，但权限保护级别应该被检查。[android:exported=true]'),
    },
    'a_prot_danger_appl': {
        'title': ('<strong>%s</strong> (%s)受application级别权限保护，但权限保护级别应该被检查。'
                  '</br>%s <br>[android:exported=true]'),
        'level': 'high',
        'description': ("""%s被发现与其他应用程序共享。因此，任何在设备上其他应用都可以访问它。它被application级别权限保护着，
        然而，权限设置为danger。这意味着恶意应用程序可以请求和获取允许并与组件交互。如果设置为signature，只适用于申请用相同的证书签名可以获得许可。
        """),
        'name': ('受application级别权限保护，但权限保护级别应该被检查。[android:exported=true]'),
    },
    'a_prot_unknown_appl': {
        'title': ('<strong>%s</strong> (%s)受application级别权限保护，但权限保护级别应该被检查。'
                  '</br>%s <br>[android:exported=true]'),
        'level': 'high',
        'description': ("""
        %s被发现与其他应用程序共享.因此，任何在设备上其他应用都可以访问它。它被application级别权限保护着
        在分析中没有定义的权限应用程序。因此，保护水平应该在定义权限的地方检查权限。如果
        它被设置为正常或危险，恶意申请可以请求并获得权限和与组件交互。如果它被设置为
        signature，只有用相同签名的应用程序证书可以获得权限。
        """),
        'name': ('受application级别权限保护，但权限保护级别应该被检查。'
                 '[android:exported=true]'),
    },
    'a_not_protected': {
        'title': ('<strong>%s</strong> (%s) 未被保护。'
                  ' <br>[android:exported=true]'),
        'level': 'high',
        'description': ('%s 被发现与其他应用程序共享,因此任何其他设备上的应用都可以访问它。'),
        'name': '未被保护。 [android:exported=true]',
    },
    'a_not_protected_filter': {
        'title': ('<strong>%s</strong> (%s) 未被保护。<br>'
                  '存在一个intent-filter.'),
        'level': 'high',
        'description': ("""%s 被发现与其他应用程序共享,因此任何其他设备上的应用都可以访问它。 
                            intent-filter的存在表明%s被显式导出"""),
        'name': '存在一个未被保护的intent-filter。',
    },
    'a_improper_provider': {
        'title': '不适当的 Content Provider 权限<br>[%s]',
        'level': 'high',
        'description': ("""一个 content provider 权限被设置为允许从设备上的任何其他应用程序访问。
                    内容提供者可能包含关于应用程序的敏感内容信息，因此不应该分享。"""),
        'name': '不适当的 Content Provider 权限',
    },
    'a_dailer_code': {
        'title': ('Dailer Code: %s Found'
                  ' <br>[android:scheme="android_secret_code"]'),
        'level': 'high',
        'description': ("""
        发现了一个代码。这些代码,当进入拨号器时授予访问隐藏可能包含敏感信息的内容。
        """),
        'name': ('Dailer Code: Found '
                 '<br>[android:scheme="android_secret_code"]'),
    },
    'a_sms_receiver_port': {
        'title': '数据短信接收端设置在端口上: %s Found<br>[android:port]',
        'level': 'high',
        'description': ("""
        二进制短信接收器被配置为监听在一个端口。发送到设备的二进制短信是被开发者
        申请以任何方式处理的东西。这个短信中的数据应该是应用程序适当地验证。
        此外,应用程序应该假定SMS是收到的消息来自一个不可信的来源。”
        """),
        'name': '数据短信接收端设置在端口上: Found<br>[android:port]',
    },
    'a_high_intent_priority': {
        'title': '优先级高的Intent (%s)<br>[android:priority]',
        'level': 'medium',
        'description': ("""
        通过设置一个高于另一个意图优先级的Intent，应用程序有效地覆盖其他请求。
        """),
        'name': '优先级高的Intent [android:priority]',
    },
    'a_high_action_priority': {
        'title': '行动的优先级高 (%s)<br>[android:priority] ',
        'level': 'medium',
        'description': ("""
        通过设置一个行动优先级高于另一个动作，应用程序有效覆盖其他请求。
        """),
        'name': '行动的优先级高 [android:priority]',
    },
}
