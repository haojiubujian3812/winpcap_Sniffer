#pragma once
/*
*	�������ڲ������ݰ����Ϊת���ļ�
*   �����Ƕ�Ĭ�ϱ����ת���ļ�������ָ��λ��
*/
#include "stdafx.h"
#include "Packet.h"
class PacketDumper
{
private:
	CString		m_path;			// ת���ļ�Ĭ�ϴ洢·��

public:
	PacketDumper();
	~PacketDumper();

	void setPath(CString path);
	CString getPath();
	//CString getFileName();

	void dump(CString path);
	void copyFile(CFile* dest, CFile* src);
};

