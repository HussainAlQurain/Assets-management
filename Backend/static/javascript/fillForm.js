$(document).ready(function(){

  $("#eID").keyup(function(){
    tmp = $("#eID").val()

    //alert(tmp)
    
    if (tmp=="found")
    {

      $("#dpt").val("test");
      $("#name").val("test");
    }

  });

});

function searchID(eID){
  
}