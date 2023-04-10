function responseOK(data) {
    console.log(data);
    // var dialog = document.getElementById('dialog');
    // var dialogContent = document.getElementById('dialogContent');
    // dialogContent.textContent = data.message;
    // dialog.style.display='block'
    // showLoading(false)
    window.location.href = '/'
}


function setup(ev)
{
    showLoading(true)
    ev.preventDefault();
    var form_data = new FormData(this)
    // form_data.append("database", document.getElementById('database').value);
    // form_data.append("storage", document.getElementById('storage').value);
    db1 = document.getElementById('database')
    db2 = document.getElementById('database2')
    file1 = document.getElementById('storage')
    file2 = document.getElementById('storage2')
    ok = true
    if (db2 != null){
        db1val = db1.value
        db2val = db2.value
        if (db1val != db2val){
            ok = false
            showDialog("database pass not match")
        }
        else
            ok = true
    }

    if (ok && (file2 != null)){
        db1val = file1.value
        db2val = file2.value
        if (db1val != db2val){
            ok = false
            showDialog("storage pass not match")
        }
        else
            ok = true
    }
    if (ok){
        $.ajax({
            url: '/setup',
            method: 'POST',
            cache: false,
            contentType: false,
            processData: false,
            data: form_data,
            success: responseOK,
            error: onResponseError
        });
    }
    else{
        showLoading(false)
    }

}

$(function(){
    $('#setup').on('submit', setup);
});