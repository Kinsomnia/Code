package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
)

var backupDir, dirPath string

func isDangerousFile(filename string) bool {
	fmt.Println("开始检测是否是危险文件")
	var isDangerous bool
	i := 0
	// 读取关键字文件，里面可以是危险函数如system()等
	keywordsFile, err := os.Open("keywords.txt")
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer keywordsFile.Close()

	// 将读取到的关键字以切片的形式储存
	keywordsScanner := bufio.NewScanner(keywordsFile)
	var keywords []string
	for keywordsScanner.Scan() {
		keyword := keywordsScanner.Text()
		keywords = append(keywords, keyword)
	}

	// 读取目标文件内容
	targetFile, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer targetFile.Close()

	// 匹配关键字，输出匹配的关键字，被匹配到的行号以及内容，直到匹配到最后一个关键字
	targetScanner := bufio.NewScanner(targetFile)
	for targetScanner.Scan() {
		line := targetScanner.Text()
		i++
		for _, keyword := range keywords {
			if strings.Contains(line, keyword) {
				fmt.Println("Keyword found:", keyword)
				fmt.Printf("Line: %d %s\n", i, line)
				isDangerous = true
			}
			if keyword == "username" {
				break
			}
		}
	}

	if err := targetScanner.Err(); err != nil {
		fmt.Println(err)
		return false
	}
	if isDangerous == true {
		fmt.Println(filename, "含有危险函数")
	}
	return isDangerous
}

func containsKeyword(s string, keyword string) bool {
	return len(s) >= len(keyword) && s[:len(keyword)] == keyword
}

func backupAndDeleteFile(filePath string) {
	backupPath := filepath.Join(backupDir, filepath.Base(filePath))

	err := os.Rename(filePath, backupPath)
	if err != nil {
		log.Println("备份文件失败:", err)
		return
	}

	fmt.Println("检测到恶意文件:", filePath)
	fmt.Println("已备份文件到:", backupPath)
}

func monitorFileChanges(dirPath string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsDir() {
			err = watcher.Add(path)
			if err != nil {
				log.Println("添加文件监视失败:", path)
			}
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				switch {
				case event.Op&fsnotify.Create == fsnotify.Create:
					fmt.Println("文件的路径是", event.Name)
					if isDangerousFile(event.Name) {
						backupAndDeleteFile(event.Name)
					} else {
						fmt.Println("新建文件或文件夹:", event.Name)
					}
				case event.Op&fsnotify.Write == fsnotify.Write:
					if isDangerousFile(event.Name) {
						backupAndDeleteFile(event.Name)
					} else {
						fmt.Println("修改文件:", event.Name)
					}
				case event.Op&fsnotify.Remove == fsnotify.Remove:
					fmt.Println("删除文件或文件夹:", event.Name)
				case event.Op&fsnotify.Rename == fsnotify.Rename:
					if isDangerousFile(event.Name) {
						backupAndDeleteFile(event.Name)
					} else {
						fmt.Println("重命名文件或文件夹:", event.Name)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("错误:", err)
			}
		}
	}()

	<-make(chan struct{})
}

func Monitor() {
	fmt.Println("请输入监控文件的路径：")
	fmt.Scan(&dirPath)
	fmt.Println("请输入备份文件的路径：")
	fmt.Scan(&backupDir)
	monitorFileChanges(dirPath)
}

