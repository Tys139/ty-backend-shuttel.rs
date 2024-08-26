#[macro_use]
extern crate rocket;
#[macro_use]
extern crate lazy_static;

use rocket::{http::Method, http::Status, serde::json::Json, State};
use rocket_cors::{CorsOptions, AllowedOrigins};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm};
use rocket::serde::{Deserialize, Serialize};
use rocket::request::{FromRequest, Outcome};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use dashmap::DashMap;
use std::net::IpAddr;
use reqwest::Client;
use serde_json::{json, Value};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use regex::Regex;
use shuttle_runtime::SecretStore;

#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse {
    token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize,
    iat: usize,
}

struct JwtToken(String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for JwtToken {
    type Error = ();

    async fn from_request(request: &'r rocket::Request<'_>) -> Outcome<Self, Self::Error> {
        let token = request.headers().get_one("Authorization");
        let state = request.rocket().state::<MyState>().unwrap();
           // Print the token, secret keyword, and JWT secret for debugging
        //   println!("Received token: {:?}", token);
        //   println!("Secret keyword: {}", state.secret_keyword);
         //  println!("JWT secret: {}", state.jwt_secret);
   
        match token {
            Some(token) if token.starts_with("Bearer ") => {
                let token = token[7..].to_string();
                if token == state.secret_keyword || verify_token(&token, &state.jwt_secret) {
                    Outcome::Success(JwtToken(token))
                } else {
                    Outcome::Error((Status::Unauthorized, ()))
                }
            }
            _ => Outcome::Error((Status::Unauthorized, ())),
        }
    }
}

lazy_static! {
    static ref REQUEST_COUNT: DashMap<(IpAddr, String), (u32, u64)> = DashMap::new();
}

struct RateLimitGuard {
    endpoint: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RateLimitGuard {
    type Error = ();

    async fn from_request(request: &'r rocket::Request<'_>) -> Outcome<Self, Self::Error> {
        let ip = request.client_ip().unwrap_or(IpAddr::from([0, 0, 0, 0]));
        println!("Received ip: {:?}", ip);
        let endpoint = request.uri().path().to_string();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let mut entry = REQUEST_COUNT.entry((ip, endpoint.clone())).or_insert((0, now));
        let (count, last_reset) = entry.value_mut();

        if now - *last_reset > 7 * 3600 {
            // Reset if 7 hours have passed
            *count = 1;
            *last_reset = now;
        } else if *count >=30 {
            // Rate limit exceeded
            return Outcome::Error((Status::TooManyRequests, ()));
        } else {
            // Increment count
            *count += 1;
        }

        Outcome::Success(RateLimitGuard { endpoint })
    }
}

fn verify_token(token: &str, secret: &str) -> bool {
    let validation = Validation::new(Algorithm::HS256);
    match decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &validation) {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[get("/get_token")]
fn get_token(state: &State<MyState> ,_rate_limit: RateLimitGuard) -> Json<TokenResponse> {
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap() + Duration::new(7 * 3600, 0);

    let claims = Claims {
        exp: expiration.as_secs() as usize,
        iat: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize,
    };

    let header = Header::new(Algorithm::HS256);
    let token = encode(&header, &claims, &EncodingKey::from_secret(state.jwt_secret.as_bytes()))
        .expect("Failed to encode token");

    Json(TokenResponse { token })
}

#[derive(Debug, Serialize)]
struct LocationResponse {
    country: String,
    city: String,
    latitude: f64,
    longitude: f64,
}

async fn get_location(ip: &str, api_key: &str) -> Result<LocationResponse, reqwest::Error> {
    let url = format!("https://api.ip2location.io/?key={}&ip={}", api_key, ip);
    println!("message message: {:?}", url);
    let client = Client::new();
    let response = client.get(&url).send().await?;
    let json: Value = response.json().await?;
    
    Ok(LocationResponse {
        country: json["country_name"].as_str().unwrap_or("Unknown").to_string(),
        city: json["city_name"].as_str().unwrap_or("Unknown").to_string(),
        latitude: json["latitude"].as_f64().unwrap_or(0.0),
        longitude: json["longitude"].as_f64().unwrap_or(0.0),
    })
}

#[get("/location/<ip>")]
async fn get_location_endpoint(ip: String, state: &State<MyState>, _token: JwtToken, _rate_limit: RateLimitGuard) -> Result<Json<LocationResponse>, Status> {
    match get_location(&ip, &state.ip2location_api_key).await {
        Ok(location) => Ok(Json(location)),
        Err(_) => Err(Status::InternalServerError),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ChatCompletionRequest {
    role: String,
    content: String,
    model: String,
}

#[derive(Debug, Serialize)]
struct ChatCompletionResponse {
    messages: Vec<Value>,
}

async fn get_chat_completion(request: &ChatCompletionRequest, groq_api_key: &str) -> Result<ChatCompletionResponse, reqwest::Error> {
    let client = Client::new();
   // println!("data goodgod: {:?}", request.role);
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", groq_api_key)).unwrap());




    let body = json!({
        "messages": [
            {
                "role": request.role,
                "content": request.content
            }
        ],
        "model": request.model,
        "temperature": 1,
        "max_tokens": 8192,
        "top_p": 1,
        "stream": false,
        "stop": null
    });
    println!("message message: {:?}", body);
    let response = client.post("https://api.groq.com/openai/v1/chat/completions")
        .headers(headers)
        .json(&body)
        .send()
        .await?
        .json::<Value>()
        .await?;

    let messages = response["choices"][0]["message"]["content"]
        .as_str()
       .unwrap_or("{}")
      .parse::<Value>()
      .unwrap_or(json!({}));
        let messages1 = response
        .get("choices")
        .and_then(|choices| choices.get(0))
        .and_then(|first_choice| first_choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(|content| content.as_str())
        .unwrap_or("No response");; 
   println!("message message: {:?}", messages1);
    Ok(ChatCompletionResponse {
        messages: vec![json!(messages1)],
    })
}

#[post("/goodgodzilla", data = "<request>")]
async fn goodgodzilla(request: Json<ChatCompletionRequest>, state: &State<MyState>, _token: JwtToken, _rate_limit: RateLimitGuard) -> Result<Json<ChatCompletionResponse>, Status> {

    match get_chat_completion(&request, &state.groq_api_key).await {
        Ok(response) => Ok(Json(response)),
        Err(_) => Err(Status::InternalServerError),
    }
}

#[get("/test_auth")]
fn test_auth(_token: JwtToken, _rate_limit: RateLimitGuard) -> &'static str {
    "Access granted with valid JWT or secret key!"
}

#[derive(Debug, Serialize, Deserialize)]
struct EmailCheckRequest {
    email: String,
}

#[derive(Debug, Serialize)]
struct EmailCheckResponse {
    is_valid_format: bool,
    is_business: bool,
}

fn is_valid_email(email: &str) -> bool {
    let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    email_regex.is_match(email)
}

fn is_business_email(email: &str) -> bool {
    let common_personal_domains = vec![
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
        "icloud.com", "mail.com", "protonmail.com", "yandex.com"
    ];
    
    let domain = email.split('@').nth(1).unwrap_or("");
    !common_personal_domains.contains(&domain)
}

#[post("/check_email", data = "<request>")]
fn check_email(request: Json<EmailCheckRequest>, _token: JwtToken) -> Json<EmailCheckResponse> {
    let is_valid = is_valid_email(&request.email);
    let is_business = is_business_email(&request.email);
    
    Json(EmailCheckResponse {
        is_valid_format: is_valid,
        is_business: is_valid && is_business,
    })
}

#[derive(Debug, Serialize)]
struct ModelResponse {
    models: Vec<Value>,
}

async fn get_models(groq_api_key: &str) -> Result<ModelResponse, reqwest::Error> {
    let client = Client::new();

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", groq_api_key)).unwrap());

    let response = client.get("https://api.groq.com/openai/v1/models")
        .headers(headers)
        .send()
        .await?
        .json::<Value>()
        .await?;

    let models = response["data"].as_array().unwrap_or(&Vec::new()).clone();

    Ok(ModelResponse { models })
}

#[get("/goodgodzillamodels")]
async fn goodgodzillamodels(state: &State<MyState>, _token: JwtToken, _rate_limit: RateLimitGuard) -> Result<Json<ModelResponse>, Status> {
    match get_models(&state.groq_api_key).await {
        Ok(response) => Ok(Json(response)),
        Err(_) => Err(Status::InternalServerError),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct EmailRequest {
    to: String,
}

#[post("/send_email", data = "<email_request>")]
async fn send_email(email_request: Json<EmailRequest>, state: &State<MyState>, _token: JwtToken) -> Result<Status, Status> {
    let client = Client::new();
    let mailer_send_api_key = &state.mailer_send_api_key;

    // Construct the email data on the backend
    let email_data = json!({
        "to": [{"email": email_request.to}],
        "from": {"email": "your@email.com"}, // Replace with your email
        "subject": "New Attachment Test",
        "html": "<p>Hello world!</p>",
        "attachments": [
            {
                "filename": "attachment.jpg",
                "content": "BASE64_ENCODED_CONTENT_HERE"
            }
        ]
    });

    let response = client.post("https://api.mailersend.com/v1/email")
        .header(AUTHORIZATION, format!("Bearer {}", mailer_send_api_key))
        .header(CONTENT_TYPE, "application/json")
        .json(&email_data)
        .send()
        .await;

    match response {
        Ok(_) => Ok(Status::Ok),
        Err(_) => Err(Status::InternalServerError),
    }
}

struct MyState {
    groq_api_key: String,
    jwt_secret: String,
    ip2location_api_key: String,
    secret_keyword: String,
    mailer_send_api_key: String,
}

#[shuttle_runtime::main]
async fn rocket(#[shuttle_runtime::Secrets] secrets: SecretStore) -> shuttle_rocket::ShuttleRocket {
    let allowed_origins = vec![
        "https://tathagatyash.com".to_string(),
        "https://ty13.work".to_string(),
        "https://tathagatyash.vercel.app/".to_string(),
        //"http://127.0.0.1:8000".to_string(),
       // "http://127.0.0.1:5173".to_string(),
       //"http://0.0.0.0:8000".to_string(), // For local development
    ];

    let cors = CorsOptions::default()
        .allowed_origins(AllowedOrigins::some_exact(&allowed_origins))
        .allowed_methods(
            vec![Method::Get, Method::Post, Method::Patch]
                .into_iter()
                .map(From::from)
                .collect(),
        )
        .allow_credentials(true)
        .to_cors()
        .expect("Failed to create CORS");

    let groq_api_key = secrets.get("GROQ_API_KEY").expect("GROQ_API_KEY must be set");
    let jwt_secret = secrets.get("JWT_SECRET").expect("JWT_SECRET must be set");
    let ip2location_api_key = secrets.get("IP2LOCATION_API_KEY").expect("IP2LOCATION_API_KEY must be set");
    let secret_keyword = secrets.get("SECRET_KEYWORD").expect("SECRET_KEYWORD must be set");
    let mailer_send_api_key = secrets.get("MAILER_SEND_API_KEY").expect("MAILER_SEND_API_KEY must be set");

    let state = MyState {
        groq_api_key,
        jwt_secret,
        ip2location_api_key,
        secret_keyword,
        mailer_send_api_key,
    };

    let rocket = rocket::build()
        .mount("/", routes![
            get_token,
            get_location_endpoint,
            goodgodzilla,
            check_email,
            goodgodzillamodels,
            send_email,
            test_auth,
        ])
        .manage(state)
        .attach(cors);

    Ok(rocket.into())
}