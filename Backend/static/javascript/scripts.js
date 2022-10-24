<script type="text/javascript">
  var table = document.getElementById("myTable");
  var rows = document.getElementsByTagName("tr");
   for(i = 1; i < rows.length; i++) {
  var currentRow = table.rows[i];
   currentRow.onclick = function() {
  // Array.from(this.parentElement.children).forEach(function(el){
  // el.classList.remove('selected-row');

  [...this.parentElement.children].forEach((el) => el.classList.remove('selected-row'));
   this.classList.add('selected-row');
   }};
  // using spread operator
  </script>