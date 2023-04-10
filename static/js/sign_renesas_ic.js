$(document).ready(function(){
    $("#save_new_param").prop("checked", false);
});


function get_help_cmd(toolname, paramid, param = null){
    
    if (param == null){
        var boot_param = document.getElementById('boot_param');
        if (boot_param != null){
            param = boot_param.value;
        }
    }
    if (param != null)
    {
        showLoading(true)
        if (paramid != null){
            url = `/sign/${toolname}?action=help&cmdid=${param}&paramid=${paramid}`
        }
        else {
            url = `/sign/${toolname}?action=help&cmdid=${param}`
        }
        console.log(url)
        $.ajax({
            url:  url,
            method: 'POST',
            success: responseHelp,
            error: onResponseError
        });
    }
    else{
        alert("invalid value")
    }
 
}


function downloadfile(toolname, paramid, param = null){
    if (param == null){
        var boot_param = document.getElementById('boot_param');
        if (boot_param != null){
            param = boot_param.value;
        }
    }
    if (param != null)
    {
        host = window.location.origin
        url = ""
        var element = document.createElement('a');

        if (paramid != null){
            element.download = paramid;
            url = `${host}/sign/${toolname}?action=download&cmdid=${param}&paramid=${paramid}`
        }
        else {
            element.download = param;
            url = `${host}/sign/${toolname}?action=download&cmdid=${param}`
        }
        element.href = url;
        element.style.display = 'none';
        document.body.appendChild(element);
    
        element.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(element);
    }
    else{
        alert("invalid value")
    }
    
}

function on_save_change(value)
{
    var custom_name = document.getElementById('custom_name');
    if (value == true){
        custom_name.disabled = false
        // div.style.display = "block";
      } else {
        custom_name.disabled = true
        // div.style.display = "none";
      }

      var custom_desc = document.getElementById('custom_desc');
      if (value == true){
            custom_desc.disabled = false
          // div.style.display = "block";
        } else {
            custom_desc.disabled = true
          // div.style.display = "none";
        }
}