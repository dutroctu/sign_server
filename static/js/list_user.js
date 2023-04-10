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

function activate_user(userid,username,activate)
{
    var i;
    var total = 3
    var ok = 0
    var act = "activate"
    if (activate != 1)
        act = "deactivate"
    for (i = 0; i < total; i++) {
        var r = confirm(`Are you sure to ${act} user '${username}' ? \nConfirmed ${i}/${total}`);
        if (r == true) {
            ok ++
        } else {
            break
        }
    }

    if (ok >= total){
        showLoading(true)
        var dict = {userid : userid, username:username,activate:activate};
        $.ajax({
            url: '/activate_user',
            method: 'POST',
            data : JSON.stringify(dict),
            contentType: "application/json",
            success: responseOK,
            error: onResponseError
        });
    }
    else{
        alert(`Not enough confirmation to ${act} (need ${total})\nDon't activate user'${username}'`)
    }

}


function reset_password(userid,username)
{
    var i;
    var total = 3
    var ok = 0
    for (i = 0; i < total; i++) {
        var r = confirm(`Are you sure to Reset password for user '${username}' ? \nConfirmed ${i}/${total}`);
        if (r == true) {
            ok ++
        } else {
            break
        }
    }

    if (ok >= total){
        showLoading(true)
        var dict = {userid : userid, username:username};
        $.ajax({
            url: '/resetpass',
            method: 'POST',
            data : JSON.stringify(dict),
            contentType: "application/json",
            success: responseOK,
            error: onResponseError
        });
    }
    else{
        alert(`Not enough confirmation to reset password (need ${total})\n`)
    }

}


function delete_user(userid,username, force)
{
    var i;
    var total = 3
    var ok = 0
    if (force == 1)
        total = 5
    for (i = 0; i < total; i++) {
        var r;
        if (force == 1)
            r = confirm(`Are you sure to FORCE delete user '${username}' ? \nConfirmed ${i}/${total}`);
        else
            r = confirm(`Are you sure to delete user '${username}' ? \nConfirmed ${i}/${total}`);

        if (r == true) {
            ok ++
        } else {
            break
        }
    }

    if (ok >= total){
        showLoading(true)
        var dict = {userid:userid, username:username, force:force};
        $.ajax({
            url: '/delete_user',
            method: 'POST',
            data : JSON.stringify(dict),
            contentType: "application/json",
            success: responseOK,
            error: onResponseError
        });
    }
    else{
        alert(`Not enough confirmation to delete (need ${total})\nDon't delete user '${username}'`)
    }

}