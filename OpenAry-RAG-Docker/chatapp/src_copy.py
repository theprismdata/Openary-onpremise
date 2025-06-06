import os
import shutil
from pathlib import Path

def copy_files_recursively_flat(source_dir, destination_dir):
    """
    재귀적으로 폴더를 검색하면서 모든 파일을 destination_dir로 평면적(flat)으로 복사합니다.
    
    Args:
        source_dir (str): 소스 디렉토리 경로
        destination_dir (str): 대상 디렉토리 경로
    """
    # 대상 디렉토리가 없으면 생성
    if not os.path.exists(destination_dir):
        os.makedirs(destination_dir)
    
    # 소스 디렉토리 내의 모든 항목 순회
    for root, dirs, files in os.walk(source_dir):
        for file in files:
            source_path = os.path.join(root, file)
            print(root, file)
            
            # 파일명 충돌을 방지하기 위해 상대 경로의 디렉토리 구분자를 언더스코어로 대체
            # rel_path = os.path.relpath(source_path, source_dir)
            # flat_filename = rel_path.replace(os.path.sep, '_')
            
            # 대상 경로 생성
            # dest_path = os.path.join(destination_dir, flat_filename)
            
            # 파일 복사
            # shutil.copy2(source_path, dest_path)
            # print(f"파일 복사됨: {source_path} -> {dest_path}")

def main():
    # 현재 작업 디렉토리
    current_dir = "src" #os.getcwd()
    if os.path.exists("./backup_src") == False:
        os.makedirs("./backup_src")
    
    # 대상 디렉토리 (backup_src)
    target_dir = "./backup_src"
    
    print(f"현재 디렉토리 '{current_dir}'에서 '{target_dir}'로 파일을 복사합니다...")
    copy_files_recursively_flat(current_dir, target_dir)
    print("복사 완료!")

if __name__ == "__main__":
    main()