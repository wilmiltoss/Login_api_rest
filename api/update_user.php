<?php
//8.1 Crear un archivo para actualizar la cuenta de usuario
// required headers
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Max-Age: 3600");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");
 
 //8.2 Incluir archivos para decodificar JWT
// required to encode json web token
include_once 'config/core.php';
include_once 'libs/php-jwt-master/src/BeforeValidException.php';
include_once 'libs/php-jwt-master/src/ExpiredException.php';
include_once 'libs/php-jwt-master/src/SignatureInvalidException.php';
include_once 'libs/php-jwt-master/src/JWT.php';
use \Firebase\JWT\JWT;
 
 //8.4 Recuperar JWT dado
// files needed to connect to database
include_once 'config/database.php';
include_once 'objects/user.php';
 
// get database connection
$database = new Database();
$db = $database->getConnection();
 
// instantiate user object
$user = new User($db);
 
// get posted data
$data = json_decode(file_get_contents("php://input"));
 
// get jwt
$jwt=isset($data->jwt) ? $data->jwt : "";
 
// if jwt is not empty
//8.5 Decode JWT if it exists
if($jwt){
 
    // if decode succeed, show user details
    try {
 
        // decode jwt
        $decoded = JWT::decode($jwt, $key, array('HS256'));
 		
 		//8.7 Establecer valores de propiedad del usuario
        // set user property values
		$user->firstname = $data->firstname;
		$user->lastname = $data->lastname;
		$user->email = $data->email;
		$user->password = $data->password;
		$user->id = $decoded->data->id;
 		
 		//8.8 Usar el método update ()
		// update the user record
		if($user->update()){

			//8.10 Re-generate JWT
		    // we need to re-generate jwt because user details might be different
			$token = array(
			   "iss" => $iss,
			   "aud" => $aud,
			   "iat" => $iat,
			   "nbf" => $nbf,
			   "data" => array(
			       "id" => $user->id,
			       "firstname" => $user->firstname,
			       "lastname" => $user->lastname,
			       "email" => $user->email
			   )
			);
			$jwt = JWT::encode($token, $key);
			 
			// set response code
			http_response_code(200);
			 
			// response in json format
			echo json_encode(
			        array(
			            "message" => "User was updated.",
			            "jwt" => $jwt
			        )
			    );
		}
		 
		// message if unable to update user
		else{
		    // set response code
		    http_response_code(401);
		 
		    // show error message
		    echo json_encode(array("message" => "Unable to update user."));
		}
    }
 
 //8.6 Mostrar mensaje de error si falla la decodificación
 // if decode fails, it means jwt is invalid
catch (Exception $e){
 
    // set response code
    http_response_code(401);
 
    // show error message
    echo json_encode(array(
        "message" => "Access denied.",
        "error" => $e->getMessage()
    ));
}
}
 
// show error message if jwt is empty
else{
 
    // set response code
    http_response_code(401);
 
    // tell the user access denied
    echo json_encode(array("message" => "Access denied."));
}
?>