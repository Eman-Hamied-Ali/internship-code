$(document).ready(function() {

	$('form').on('submit', function(event) {

		$.ajax({
			data : {
				job_title : $('#field-2').val(),
				file : $('#file-field').val()
			},
			type : 'POST',
			url : '/test'
		})
		.done(function(data) {

			if (data.result) {
				$('#successAlert').text(data.name).show();
				$('#errorAlert').hide();
			}
			else {
				$('#errorAlert').text(data.error).show();
				$('#successAlert').hide();
				
			}

		});

		event.preventDefault();

	});

});