/*
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
namespace Google.Plus.Samples.Quickstart
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Text;
    using System.Web;

    using Google.Apis.Authentication.OAuth2;

    using Newtonsoft.Json;

    /// <summary>
    /// A utility class used to manually exchange an authorization code for
    /// OAuth2 credentials. When "postmessage" is accepted as a redirect URI for
    /// the client library, you should no longer need to use this utility.
    /// </summary>
    /// @author class@google.com (Gus Class)
    public class ManualCodeExchanger
    {
        /// <summary>
        /// Exchanges an OAuth 2 authorization code for OAuth 2 credentials.
        /// </summary>
        /// <param name="code">The OAuth 2 authorization code from the sign-in
        /// button.</param>
        /// <returns>An OAuth v2 response object retrieved from JSON.</returns>
        public static OAuthResponseObject ExchangeCode(string code)
        {
            // The request will be made to the authentication server.
            WebRequest request = WebRequest.Create(
                GoogleAuthenticationServer.Description.TokenEndpoint);

            // You must use POST for the code exchange.
            request.Method = "POST";

            // Create POST data.
            string postData = FormPostData(code);
            byte[] byteArray = Encoding.UTF8.GetBytes(postData);

            // Set up the POST request for the code exchange.
            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = byteArray.Length;

            // Perform the POST and retrieve the server response with
            // the access token and/or the refresh token.
            string responseFromServer;
            using (var reqData = request.GetRequestStream())
            {
                reqData.Write(byteArray, 0, byteArray.Length);
                using (var reader = new StreamReader(request.GetResponse()
                    .GetResponseStream()))
                {
                    responseFromServer = reader.ReadToEnd();
                }
            }

            // Convert the response JSON to an object and return it.
            return JsonConvert.DeserializeObject<OAuthResponseObject>(
                responseFromServer);
        }

        /// <summary>
        /// Creates the string representing the POST data for authorization.
        /// </summary>
        /// <param name="code">The authorization code to be exchanged for
        /// tokens.</param>
        /// <returns>The POST string.</returns>
        public static string FormPostData(string code)
        {
            return String.Format("code={0}&client_id={1}&client_secret={2}&"
                + "redirect_uri=postmessage&grant_type=authorization_code",
                code,
                Signin.CLIENT_ID,
                Signin.CLIENT_SECRET);
        }
    }

    /// <summary> Encapsulates OAuth 2.0 response data.</summary>
    public class OAuthResponseObject
    {
        /// <summary>The OAuth 2 access token.</summary>
        [Newtonsoft.Json.JsonPropertyAttribute("access_token")]
        public string AccessToken { get; set; }

        /// <summary>The OAuth 2 refresh token.</summary>
        [Newtonsoft.Json.JsonPropertyAttribute("refresh_token")]
        public string RefreshToken { get; set; } 

        /// <summary>The OAuth 2 one-time-use code.</summary>
        [Newtonsoft.Json.JsonPropertyAttribute("code")]
        public string Code { get; set; }

        /// <summary>The seconds until expiration.</summary>
        [Newtonsoft.Json.JsonPropertyAttribute("expires_in")]
        public int ExpiresIn { get; set; }

        /// <summary>The OAuth 2 ID token.</summary>
        [Newtonsoft.Json.JsonPropertyAttribute("id_token")]
        public string IdToken { get; set; }
    }
}
