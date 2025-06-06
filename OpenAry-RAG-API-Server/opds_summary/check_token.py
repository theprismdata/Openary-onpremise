import tiktoken

def encoding_getter(encoding_type: str):
    return tiktoken.encoding_for_model(encoding_type)

def tokenizer(string: str, encoding_type: str) -> list:

    encoding = encoding_getter(encoding_type)
    #print (encoding)
    tokens = encoding.encode(string)
    return tokens

def token_counter(string: str, encoding_type: str) -> int:

    num_tokens = len(tokenizer(string, encoding_type))
    return num_tokens

def main():
    prompt_text2 = "현재를 즐겨라"

    num_tokens=token_counter(prompt_text2, "gpt-3.5-turbo")
    print(prompt_text2+"의 토큰 수는 "+ str(num_tokens) +"입니다")