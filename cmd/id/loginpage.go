package main

import (
	"html/template"
)

var loginHtmlTpl, _ = template.New("_").Parse(`
<!doctype html>

<html>
<head>
	<title>Login</title>
	<style>
	th {
		text-align: left;
	}

	.passive {
		color: #c0c0c0;
	}
	</style>
</head>

<body style="width: 600px; margin: auto; text-align: center;">

<p>Logging in to</p>

<p title="{{.Next}}">
	<span class="passive">https://</span>{{.NextHumanReadable}}<span class="passive">/</span>
</p>

<form action="" method="post">
	<fieldset>
		<legend>Login</legend>

		<table>
		<tr>
			<th>Email</th>
			<td><input required type="text" name="email" placeholder="bob@example.com" /></td>
		</tr>
		<tr>
			<th>Password</th>
			<td><input required type="password" name="password" /></td>
		</tr>
		</table>

		<input type="submit" value="Login" />
	</fieldset>
</form>

<script defer>
var rememberedUsername = localStorage.getItem('id-email');
var emailField = document.querySelector('input[name=email]');
if (rememberedUsername) {
	emailField.value = rememberedUsername;
}
document.querySelector('form').onsubmit = function(e){
	localStorage.setItem('id-email', emailField.value);
}
</script>

</body>
</html>
`)
