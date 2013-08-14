using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace GPlusQuickstartCsharp
{
    public partial class fedLogin : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (Request["code"] != null)
            {
                // Perform code exchange here
                var result = ManualCodeExchanger.ExchangeCode(Request["code"]);
            }

        }
    }
}