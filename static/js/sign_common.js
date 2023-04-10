
function showLoading(show){
    var dialog = document.getElementById('loader');
    dialog.style.display= show?'block':'none'
}

function responseSilent(data) {
    responseResult(data, true);
}
function responseNotSilent(data) {
    responseResult(data, false);
}
function responseResult(data, silent=false) {
    console.log(data);
    
    var dialog = document.getElementById('dialog');
    var dialogContent = document.getElementById('dialogContent');
    var key_id = document.getElementById("key_id");
    key_id.innerHTML = "";
    textContent = null;
    if (typeof data === 'string')
    {
        textContent = "something when wrong.. are you login first?"
    }
    else if (data.code == 0)
    {
        
        const jroot = JSON.parse(data.data);
        if (jroot != null && jroot.keyList != null && jroot.keyList.length > 0 && key_id != null){
            for (let key in jroot.keyList) {
                if (jroot.keyList[key] != null)
                {
                    value = JSON.parse(jroot.keyList[key])
                    var option = document.createElement("option");
                    option.text = `${value.name} | title: ${value.title} | model: ${value.model} | project: ${value.project}`
                    option.value = value.id;
                    key_id.add(option);
                }
              }
        }
        else
        {
            textContent = "Not found key data";
        }
    }
    else
    {
        textContent = data.message;
    }
    if (textContent != null && !silent){
        dialogContent.textContent = textContent;
        dialog.style.display='block';
    }
    
    showLoading(false)
}


function get_key_list_silent()
{
    get_key_list(true)
}
function get_key_list(silent=false)
{
    keytool = document.getElementById('keytool')
    keytoolid = null;
    if (keytool != null){
        keytoolid = keytool.value
    }
    if (keytoolid != null)
    {
        showLoading(true)
        cb = responseNotSilent;
        if (silent)
            cb = responseSilent;
        $.ajax({
            url: `/view_key?keytool=${keytoolid}`,
            method: 'POST',
            contentType: "application/json",
            success: cb,
            error: onResponseError
        });
    }
    else
    {
        alert(`not found ${keytoolid}`)
    }
}

function viewListKey()
{

    keytool = document.getElementById('keytool')
    keytoolid = null;
    if (keytool != null){
        keytoolid = keytool.value
    }
    if (keytoolid != null)
    {
        window.open(`/view_key?keytool=${keytoolid}`);
    }
}

$(document).ready(get_key_list_silent);