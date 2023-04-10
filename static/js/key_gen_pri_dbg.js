
function onDebugMaskChange(selectObject) {
    var txtbox = document.getElementById('debug_mask');
    txtbox.value = selectObject.value;
    if (selectObject.value == "0")
    {
        txtbox.readonly = false;
        txtbox.value = "0x0"
    }
    else{
        txtbox.readonly = true;
    }
}
