<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="fedLogin.aspx.cs" Inherits="GPlusQuickstartCsharp.fedLogin" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
</head>
<body>
    <script type="text/javascript">
        var confirms = 0;
        function loginFinishedCallback(result) {
            console.log(result);
            if (result.access_token != null) {
                gapi.client.load('plus', 'v1', function(){
                  gapi.client.load('oauth2', 'v2', function () {
                      gapi.client.plus.people.get({ userId: 'me' }).execute(
                        function (resp) {
                            document.getElementById('name').value = resp.displayName;
                            confirms += 1;
                            if (confirms > 1) {
                                document.getElementById('form1').submit();
                            }
                        });
                  });
                  gapi.client.load('oauth2', 'v2', function () {
                    gapi.client.oauth2.userinfo.get().execute(
                        function (resp) {
                            document.getElementById('email').value = resp.email;
                            confirms += 1;
                            if (confirms > 1) {
                                document.getElementById('form1').submit();
                            }
                        });
                  });
                });
                document.getElementById('code').value = result.code;
            }
        }
    </script>
    <div id="signin-button" class="slidingDiv">
        <div class="g-signin" data-callback="loginFinishedCallback"
            data-approvalprompt="force"
            data-clientid="YOUR_CLIENT_ID"
            data-scope="https://www.googleapis.com/auth/userinfo.email"
            data-height="short"
            data-cookiepolicy="single_host_origin"
        >
    </div>
    </div>

    
    <form id="form1" runat="server" method="post">
    <div>
        <input type="hidden" name="code" id="code" />
        <input type="hidden" name="email" id="email" />
        <input type="hidden" name="name" id="name" />
        <input type="text" name="entry"/>
        <input type="submit" value="someval" />
    </div>
    </form>
</body>
<script type="text/javascript">
  (function () {
    var po = document.createElement('script');
    po.type = 'text/javascript'; po.async = true;
    po.src = 'https://plus.google.com/js/client:plusone.js';
    var s = document.getElementsByTagName('script')[0];
    s.parentNode.insertBefore(po, s);
  })();
</script>
</html>
