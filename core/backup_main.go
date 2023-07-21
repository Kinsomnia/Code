package core

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"time"
)

func BackupMain(path string) {
	// 获取当前时间
	now := time.Now().Format("2006-01-02")

	// 创建备份文件
	filename := "backup_" + now + ".tar.gz"
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// 创建Gzip压缩器
	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()

	// 创建Tar打包器
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	// 遍历目录并添加到备份文件中
	err = filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 跳过备份文件和备份目录
		if path == filename || info.IsDir() && info.Name() == "backup" {
			return nil
		}

		// 创建文件头信息
		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return err
		}
		header.Name = path

		// 写入文件头信息
		err = tarWriter.WriteHeader(header)
		if err != nil {
			return err
		}

		// 如果是普通文件，则写入文件内容
		if info.Mode().IsRegular() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = io.Copy(tarWriter, file)
			if err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		panic(err)
	}

	// 备份完成
	println("Backup completed!")
}
