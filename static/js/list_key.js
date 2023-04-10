function responseOK(data) {
    console.log("responseOK")
    console.log(data);
    var dialog = document.getElementById('dialog');
    var dialogContent = document.getElementById('dialogContent');
    if (typeof data === 'string')
        dialogContent.textContent = "something when wrong.. are you login first?"
    else
        dialogContent.textContent = data.message;
    dialog.style.display='block'
    showLoading(false)
    var dialogReload = document.getElementById('dialogReload');
    dialogReload.style.display='block'
}


function delete_key(key_id,key_name)
{
    var i;
    var total = 3
    var ok = 0
    for (i = 0; i < total; i++) {
        var r = confirm(`Are you sure to delete key '${key_name}' (${key_id}) ? \nConfirmed ${i}/${total}`);
        if (r == true) {
            ok ++
        } else {
            break
        }
    }

    if (ok >= total){
        showLoading(true)
        var dict = {key_id : key_id};
        $.ajax({
            url: '/delete_key',
            method: 'POST',
            data : JSON.stringify(dict),
            contentType: "application/json",
            success: responseOK,
            error: onResponseError
        });
    }
    else{
        alert(`Not enough confirmation to delete (need ${total})\nDon't delete key '${key_name}' (${key_id})`)
    }

}

function set_default(key_id,key_name,set_default)
{
    var i;
    var total = 3
    var ok = 0
    var str = "set default"
    if (!set_default)
        str = "clear default"
    for (i = 0; i < total; i++) {
        var r = confirm(`Are you sure to '${str}' key '${key_name}' (${key_id}) ? \nConfirmed ${i}/${total}`);
        if (r == true) {
            ok ++
        } else {
            break
        }
    }

    if (ok >= total){
        showLoading(true)
        var dict = {key_id : key_id, default:set_default};
        $.ajax({
            url: '/setdefaultkey',
            method: 'POST',
            data : JSON.stringify(dict),
            contentType: "application/json",
            success: responseOK,
            error: onResponseError
        });
    }
    else{
        alert(`Not enough confirmation to '${str}' (need ${total})\nDon't '${str}' key '${key_name}' (${key_id})`)
    }

}
