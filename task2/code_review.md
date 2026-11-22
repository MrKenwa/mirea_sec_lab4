# Задание 2

```php
<?php

if( isset( $_GET[ 'Login' ] ) ) {
	// Get username
	$user = $_GET[ 'username' ];
	// Get password
	$pass = $_GET[ 'password' ];
	$pass = md5( $pass );
	// Check the database
	$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
	$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
	if( $result && mysqli_num_rows( $result ) == 1 ) {
		// Get users details
		$row    = mysqli_fetch_assoc( $result );
		$avatar = $row["avatar"];
		// Login successful
		$html .= "<p>Welcome to the password protected area {$user}</p>";
		$html .= "<img src=\"{$avatar}\" />";
	}
	else {
		// Login failed
		$html .= "<pre><br />Username and/or password incorrect.</pre>";
	}
	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}
?>
```

## Уязвимости

| № | Слабое место | CWE | Где и почему возникает | Последствия и условия эксплуатации | Как исправить |
|---|---|---|---|---|---|
| 1 | **SQL-инъекция** | [CWE-89 — SQL Injection](https://cwe.mitre.org/data/definitions/89.html) | `$user` напрямую вставляется в SQL: `WHERE user = '$user'`. Пользовательский ввод может стать частью синтаксиса запроса. | Обход проверки пароля и возможное извлечение данных. Проверка количества строк не устраняет инъекцию. | Использовать подготовленные запросы с параметрами. |
| 2 | **Недостаточная вычислительная сложность хеширования пароля** | [CWE-916 — Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html) | `md5($pass)` вычисляется быстро, без настройки стоимости обработки пароля. | При утечке хешей возможен быстрый офлайн-перебор паролей. | Применять `password_hash()` и `password_verify()`, например с Argon2id |
| 3 | **Отсутствие индивидуальной соли при хешировании** | [CWE-759 — Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html) | Вычисляется только `md5($pass)`, без случайного значения, уникального для пользователя. | Одинаковые пароли дают одинаковые хеши; становятся полезны заранее рассчитанные таблицы. | Использовать `password_hash()`: соль генерируется автоматически и сохраняется в составе результата. |
| 4 | **Передача пароля через URL** | [CWE-598 — Use of HTTP Request With Sensitive Query String](https://cwe.mitre.org/data/definitions/598.html) | Пароль получается из `$_GET['password']`, то есть из параметров URL. | Пароль может сохраняться в истории браузера, журналах сервера, прокси и мониторинга. | Передавать пароль в теле POST-запроса по HTTPS. |
| 5 | **XSS** | [CWE-79 — Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html) | Без HTML-экранирования выводятся: 1) `$user` в приветствии; 2) `$row['avatar']` в атрибуте `src`; 3) `mysqli_error()` внутри `<pre>`. | Возможное выполнение JavaScript в браузере. | Экранировать вывод независимо от источника данных через `htmlspecialchars(..., ENT_QUOTES \| ENT_SUBSTITUTE, 'UTF-8')`; отдельно проверять допустимость URL аватара. Технические ошибки не выводить клиенту. |
| 6 | **Раскрытие внутренних сведений через ошибки** | [CWE-209 — Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html) | `die(...)` выводит результат `mysqli_error()` или `mysqli_connect_error()`. | Возможное раскрытие частей запроса, имён объектов БД и сведений об окружении. Это помогает дальнейшим атакам. Если MySQLi выбрасывает исключение, нужно отдельно проверить его обработку. | Возвращать общее сообщение, а техническую диагностику сохранять в закрытом серверном журнале без секретов. |
| 7 | **Отсутствие проверки типа входных параметров** | [CWE-1287 — Improper Validation of Specified Type of Input](https://cwe.mitre.org/data/definitions/1287.html) | Код предполагает, что `username` и `password` — строки, но параметры PHP могут быть массивами: например, `password[]=x`. | В PHP 8 передача массива в `md5()` вызывает `TypeError`. Без внешнего обработчика запрос аварийно завершается; при включённом выводе ошибок возможна дополнительная утечка диагностики. Это не доказывает отказ всего сервиса. | До использования проверять наличие параметров и `is_string()`, отклонять неподходящий ввод. |
| 8 | **Возможная подделка запроса входа — login CSRF** | [CWE-352 — Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html) | В обработчике нет проверки CSRF-токена или происхождения запроса. | Атакующий может заставить браузер жертвы войти в аккаунт атакующего; последующие действия жертвы будут связаны с этим аккаунтом. | Использовать POST, CSRF-токен, проверку происхождения запроса и подходящие настройки cookie. |

