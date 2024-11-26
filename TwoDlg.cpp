
// TwoDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "Two.h"
#include "TwoDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//DOS头
DOS_HEADER_STRUCT DosHeader[] =
{
	2, "e_magic"      ,
	2, "e_cblp"       ,
	2, "e_cp"         ,
	2, "e_crlc"       ,
	2, "e_cparhdr"    ,
	2, "e_minalloc"   ,
	2, "e_maxalloc"   ,
	2, "e_ss"         ,
	2, "e_sp"         ,
	2, "e_csum"       ,
	2, "e_ip"         ,
	2, "e_cs"         ,
	2, "e_lfarlc"     ,
	2, "e_ovno"       ,
	2, "e_res[0]"     ,
	2, "e_res[1]"     ,
	2, "e_res[2]"     ,
	2, "e_res[3]"     ,
	2, "e_oemid"      ,
	2, "e_oeminfo"    ,
	2, "e_res2[0]"    ,
	2, "e_res2[1]"    ,
	2, "e_res2[2]"    ,
	2, "e_res2[3]"    ,
	2, "e_res2[4]"    ,
	2, "e_res2[5]"    ,
	2, "e_res2[6]"    ,
	2, "e_res2[7]"    ,
	2, "e_res2[8]"    ,
	2, "e_res2[9]"    ,
	4, "e_lfanew"     ,
};
DOS_HEADER_STRUCT* s_DosHeaderMess = DosHeader;


//文件头
FILE_HEADER_STRUCT peheader[] =
{
	2,  "Machine",
	2,  "NumberOfSections",
	4,  "TimeDateStamp",
	4,  "PointerToSymbolTable",
	4,  "NumberOfSymbols",
	2,  "SizeOfOptionalHeader",
	2,  "Characteristics"
};
FILE_HEADER_STRUCT* s_FileHeaderMess = peheader;

//可选头
PE_OPTION_HEADER_STRUCT optional[] =
{
	2, "Magic",
	1, "MajorLinkerVersion",
	1, "MinorLinkerVersion",
	4, "SizeOfCode",
	4, "SizeOfInitializedData",
	4, "SizeOfUninitializedData",
	4, "AddressOfEntryPoint",
	4, "BaseOfCode",
	4, "BaseOfData",
	4, "ImageBase",
	4, "SectionAlignment",
	4, "FileAlignment",
	2, "MajorOperatingSystemVersion",
	2, "MinorOperatingSystemVersion",
	2, "MajorImageVersion",
	2, "MinorImageVersion",
	2, "MajorSubsystemVersion",
	2, "MinorSubsystemVersion",
	4, "Win32VersionValue",
	4, "SizeOfImage",
	4, "SizeOfHeaders",
	4, "CheckSum",
	2, "Subsystem",
	2, "DllCharacteristics",
	4, "SizeOfStackReserve",
	4, "SizeOfStackCommit",
	4, "SizeOfHeapReserve",
	4, "SizeOfHeapCommit",
	4, "LoaderFlags",
	4, "NumberOfRvaAndSizes",
	8, "DataDirectory[0]",
	8, "DataDirectory[1]",
	8, "DataDirectory[2]",
	8, "DataDirectory[3]",
	8, "DataDirectory[4]",
	8, "DataDirectory[5]",
	8, "DataDirectory[6]",
	8, "DataDirectory[7]",
	8, "DataDirectory[8]",
	8, "DataDirectory[9]",
	8, "DataDirectory[10]",
	8, "DataDirectory[11]",
	8, "DataDirectory[12]",
	8, "DataDirectory[13]",
	8, "DataDirectory[14]",
	8, "DataDirectory[15]"
};
PE_OPTION_HEADER_STRUCT* s_OptHeaderMess = optional;


//节表
SECTION_TABLE section[] =
{
	8,   "Name",
	4,   "Misc",
	4,   "VirtualAddress",
	4,   "SizeOfRawData",
	4,   "PointerToRawData",
	4,   "PointerToRelocations",
	4,   "PointerToLinenumbers",
	2,   "NumberOfRelocations",
	2,   "NumberOfLinenumbers",
	4,   "Characteristics"
};
SECTION_TABLE* s_SecTableMess = section;


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CTwoDlg 对话框



CTwoDlg::CTwoDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_TWO_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CTwoDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TREE, m_tTreeFile);
	DDX_Control(pDX, IDC_LIST, m_lDataList);
}

BEGIN_MESSAGE_MAP(CTwoDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_NOTIFY(TVN_SELCHANGED, IDC_TREE, &CTwoDlg::OnSelchangedTree)
	ON_BN_CLICKED(BTN_WRITEIN, &CTwoDlg::OnBnClickedWritein)
END_MESSAGE_MAP()


// CTwoDlg 消息处理程序

BOOL CTwoDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	//获取列表大小
	m_lDataList.GetClientRect(&m_rect);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CTwoDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CTwoDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CTwoDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}
//--------------------------------------------------------------------------------------------

//树选择
void CTwoDlg::OnSelchangedTree(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMTREEVIEW pNMTreeView = reinterpret_cast<LPNMTREEVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;

	HTREEITEM hItem = m_tTreeFile.GetSelectedItem();
	CString csItem = m_tTreeFile.GetItemText(hItem);

	if (strcmp(csItem.GetBuffer(), "_IMAGE_DOS_HEADER") == 0)//DOS头
	{
		ShowDosHeader();
	}
	else if (strcmp(csItem.GetBuffer(), "Signature") == 0)//PE标识
	{
		ShowPESign();
	}
	else if (strcmp(csItem.GetBuffer(), "IMAGE_FILE_HEADER") == 0)//PE头
	{
		ShowFileHeader();
	}
	else if (strcmp(csItem.GetBuffer(), "IMAGE_OPTIONAL_HEADER32") == 0)//可选PE头
	{
		ShowOptionalHeader();
	}
	else if (strcmp(csItem.GetBuffer(), "节表") == 0)//节表
	{
		ShowSectionTable();
	}
	else if (strcmp(csItem.GetBuffer(), "地址转换") == 0)//地址转换
	{
		m_nCurrentSelect = OP_ADDRCHANGE;
	}
	else if (strcmp(csItem.GetBuffer(), "导入目录") == 0)//导入目录
	{
		ShowImport();
	}
	else if (strcmp(csItem.GetBuffer(), "导出目录") == 0)//导出目录
	{
		ShowExport();
	}
	else if (strcmp(csItem.GetBuffer(), "重定位表") == 0)//重定位表
	{
		ShowRelocation();
	}
}

//Button点击确认，写入文件
void CTwoDlg::OnBnClickedWritein()
{
	//清空树
	m_tTreeFile.DeleteAllItems();

	//获取将打开的文件信息
	if (!GetFileMess()) {
		AfxMessageBox("非PE文件");
		return;
	}
	TreeFileInit();
}

BOOL CTwoDlg::GetFileMess()
{
	/*
		1.获取文本框信息
		2.打开文件
		3.获取信息
		4.创建文件映射
		5.获取信息
	*/
	CString cFilePath;
	GetDlgItemText(DET_FILEPATH, cFilePath);
	//打开文件,获取句柄
	m_hFile = CreateFile(cFilePath.GetBuffer(),
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE == m_hFile)
	{
		AfxMessageBox("文件无法打开");
		return FALSE;
	}
	//拿到路径
	strcpy_s(m_szPath, MAX_PATH, cFilePath.GetBuffer());
	//拿到进程名
	for (int i = strlen(m_szPath) - 5; i >= 0; i--)
	{
		if (m_szPath[i] == '\\')
		{
			strcpy_s(m_szProcessName, 30, &m_szPath[i + 1]);
			break;
		}
	}
	//创建文件映射对象
	m_hFileMap = CreateFileMapping(
		m_hFile,
		NULL,
		PAGE_READWRITE,
		0,
		0,
		NULL);
	if (m_hFileMap == NULL)
	{
		AfxMessageBox("文件映射对象无法创建");
		CloseHandle(m_hFile);
		return FALSE;
	}
	//获取文件大小
	DWORD dwHigh = 0;
	m_FileSize = GetFileSize(m_hFile, &dwHigh);

	//创建映射视图,把文件全部映射到内存
	m_pView = MapViewOfFile(
		m_hFileMap,
		FILE_MAP_WRITE,
		0,
		0,
		0);
	if (m_pView == NULL)
	{
		AfxMessageBox("文件映射失败");
		CloseHandle(m_hFile);
		CloseHandle(m_hFileMap);
		return FALSE;
	}
	//获取结构体地址
	m_pDOS = (_IMAGE_DOS_HEADER*)m_pView;
	m_pNT = (_IMAGE_NT_HEADERS*)(m_pDOS->e_lfanew + (int)m_pDOS);
	m_pFILE = (IMAGE_FILE_HEADER*)((int)m_pNT + 4);
	m_pOptional = (IMAGE_OPTIONAL_HEADER32*)((int)m_pFILE + 20);
	m_pSection = (IMAGE_SECTION_HEADER*)((int)m_pOptional + m_pFILE->SizeOfOptionalHeader);

	//审核结构
	if (m_pDOS->e_magic != 0x5A4D || m_pNT->Signature != 0X4550)
	{
		AfxMessageBox("非PE结构");
		return FALSE;
	}
	//获取偏移
	m_nOffsetNT = m_pDOS->e_lfanew;
	m_nOffsetFile = m_nOffsetNT + 4;
	m_nOffsetOptional = m_nOffsetFile + sizeof(IMAGE_FILE_HEADER);
	m_nOffsetSection = m_nOffsetOptional + m_pFILE->SizeOfOptionalHeader;
	m_nOffsetFirstSection = m_pSection->PointerToRawData;

	m_nImageBase = m_pOptional->ImageBase;				//获取内存镜像基址
	m_nFileAlignment = m_pOptional->FileAlignment;		//文件对齐大小
	m_nSectionAlignment = m_pOptional->SectionAlignment;//内存对齐大小
	m_nSectionTableNum = m_pFILE->NumberOfSections;		//获取节表数量
	m_nNumberOfData = m_pOptional->NumberOfRvaAndSizes; //数据目录个数

	//地址
		//导入表偏移、地址
	int nRVAImport = m_pOptional->DataDirectory[1].VirtualAddress;//导入表的RVA
	m_nOffsetImport = nRvaToFa(nRVAImport);
	m_pImport = (IMAGE_IMPORT_DESCRIPTOR*)((int)m_pView + m_nOffsetImport);

		//导出表的偏移、地址
	int nRVAExport = m_pOptional->DataDirectory[0].VirtualAddress;//导出表的RVA
	m_nOffsetExport = nRvaToFa(nRVAExport);
	m_pExport = (IMAGE_EXPORT_DIRECTORY*)((int)m_pView + m_nOffsetExport);
		//重定位表
	m_nOffsetRelocation = nRvaToFa(m_pOptional->DataDirectory[5].VirtualAddress);
	m_nSizeOfRelocation = m_pOptional->DataDirectory[5].Size;
	m_pRelocation = (IMAGE_BASE_RELOCATION*)((int)m_pView + m_nOffsetRelocation);

	m_dwNumOfFunctions = m_pExport->NumberOfFunctions;
	m_dwNumOfNames = m_pExport->NumberOfNames;
	m_dwAddrOfFunction = m_pExport->AddressOfFunctions;
	m_dwAddrOfNames = m_pExport->AddressOfNames;
	m_dwAddrOfOrdinal = m_pExport->AddressOfNameOrdinals;
	m_dwBase = m_pExport->Base;

	return TRUE;
}

BOOL CTwoDlg::TreeFileInit()
{
	//插入进程名，返回进程的句柄
	HTREEITEM  hProcess = m_tTreeFile.InsertItem(m_szProcessName);

	//插入PE的各结构体
	//DOS头
	HTREEITEM  hDOS = m_tTreeFile.InsertItem("DOS头", NULL, NULL, hProcess);

	//DOS  _IMAGE_DOS_HEADER
	HTREEITEM  hDOSHeader = m_tTreeFile.InsertItem("_IMAGE_DOS_HEADER", NULL, NULL, hDOS);

	//PE头
	HTREEITEM  hPE = m_tTreeFile.InsertItem("PE头", NULL, NULL, hProcess);

	//NT头 _IMAGE_NT_HEADERS
	HTREEITEM  hNtHead = m_tTreeFile.InsertItem("_IMAGE_NT_HEADERS", NULL, NULL, hPE);

	//PE标识 PE
	HTREEITEM  hSignature = m_tTreeFile.InsertItem("Signature", NULL, NULL, hNtHead);

	//PE头 IMAGE_FILE_HEADER 
	HTREEITEM  hFileHead = m_tTreeFile.InsertItem("IMAGE_FILE_HEADER", NULL, NULL, hNtHead);

	//可选PE头 IMAGE_OPTIONAL_HEADER32  
	HTREEITEM  hOptionalHead = m_tTreeFile.InsertItem("IMAGE_OPTIONAL_HEADER32", NULL, NULL, hNtHead);

	//节表
	HTREEITEM  hSection = m_tTreeFile.InsertItem("节表", NULL, NULL, hProcess);

	//导入目录
	HTREEITEM  hImprotDirect = m_tTreeFile.InsertItem("导入目录", NULL, NULL, hProcess);

	//导出目录
	HTREEITEM  hExprotDirect = m_tTreeFile.InsertItem("导出目录", NULL, NULL, hProcess);

	//重定位表
	HTREEITEM  hRelocation = m_tTreeFile.InsertItem("重定位表", NULL, NULL, hProcess);
	return TRUE;
}



//虚拟地址转相对虚拟地址
int CTwoDlg::nVaToRva(int nVa)
{
	return nVa - m_nImageBase;
}
//虚拟地址转文件偏移
int CTwoDlg::nVaToFa(int nVa)
{
	return nRvaToFa(nVaToRva(nVa));
}
//相对虚拟地址转虚拟地址
int CTwoDlg::nRvaTova(int nRva)
{
	return nRva + m_nImageBase;
}
//相对虚拟地址转文件偏移
int CTwoDlg::nRvaToFa(int nRva)
{
	if (nRva < m_pSection[0].VirtualAddress|| m_nSectionTableNum == 0)
	{
		return nRva;
	}
	int nFileOffset = getFileOffsetFromAddress(nRva);
	int nMemOffset = getMemoryOffsetFromAddress(nRva);
	return nRva - nMemOffset + nFileOffset;
}
//文件偏移转相对虚拟地址
int CTwoDlg::nFaToRva(int nFa)
{
	int nFileOffset = getFileOffsetFromAddress(nFa);
	int nMemOffset = getMemoryOffsetFromAddress(nFa);
	return nFa + nMemOffset - nFileOffset;
}

//文件偏移转虚拟地址
int CTwoDlg::nFaToVa(int nFa)
{
	return nRvaTova(nFaToRva(nFa));
}


int CTwoDlg::getFileOffsetFromAddress(int address)
{
	//遍历节表
	int nEnd;
	for (int i = 0; i < m_nSectionTableNum; i++) {
		if (i == m_nSectionTableNum - 1)
		{
			nEnd = m_pOptional->SizeOfImage;
		}
		else
		{
			nEnd = m_pSection[i + 1].VirtualAddress;
		}

		// 是否在节范围内
		if (address >= m_pSection[i].VirtualAddress && address < nEnd) {
			// 返回文件偏移
			return m_pSection[i].PointerToRawData;
		}
	}

	return 0;
}

int CTwoDlg::getMemoryOffsetFromAddress(int address)
{
	//遍历节表
	int nEnd;
	for (int i = 0; i < m_nSectionTableNum; i++) {
		if (i == m_nSectionTableNum - 1)
		{
			nEnd = m_pOptional->SizeOfImage;
		}
		else
		{
			nEnd = m_pSection[i + 1].VirtualAddress;
		}
		// 是否在节范围内
		if (address >= m_pSection[i].VirtualAddress && address < nEnd) {
			return m_pSection[i].VirtualAddress;
		}
	}
	return 0;
}




void CTwoDlg::ShowDosHeader()
{
	char szTemp[100] = {};
	CString cTemp;
	//清空列表
	m_lDataList.DeleteAllItems();
	while (m_lDataList.DeleteColumn(0));

	//2.添加新标题
	m_lDataList.InsertColumn(0, _T("Value"), LVCFMT_LEFT, m_rect.right / 5);
	m_lDataList.InsertColumn(0, _T("Size"), LVCFMT_LEFT, m_rect.right / 5);
	m_lDataList.InsertColumn(0, _T("Offset"), LVCFMT_LEFT, m_rect.right / 5);
	m_lDataList.InsertColumn(0, _T("Addr"), LVCFMT_LEFT, m_rect.right / 5);
	m_lDataList.InsertColumn(0, _T("Mem"), LVCFMT_LEFT, m_rect.right / 5);
	
	int nBegin = m_nOffsetDos;
	void* pBegin = (void*)m_pDOS;

	for (int i = 0; i < 31; i++)
	{
		ZeroMemory(szTemp, 100);
		//添加成员
		m_lDataList.InsertItem(i, s_DosHeaderMess[i].pInfo);

		//添加地址
		cTemp.Format(_T("0x%p"), pBegin);
		m_lDataList.SetItemText(i, 1, cTemp);

		//添加偏移
		wsprintf(szTemp, "0X%p", nBegin);
		m_lDataList.SetItemText(i, 2, szTemp);
		nBegin = nBegin + s_DosHeaderMess[i].nSize;

		//添加大小,值
		if (s_DosHeaderMess[i].nSize == 2)
		{
			m_lDataList.SetItemText(i, 3, "WORD");

			wsprintf(szTemp, "%04X", *(WORD*)pBegin);
			m_lDataList.SetItemText(i, 4, szTemp);
			pBegin = (void*)((int)pBegin + 2);
		}
		else
		{
			m_lDataList.SetItemText(i, 3, "DWORD");

			wsprintf(szTemp, "%08X", *(DWORD*)pBegin);
			m_lDataList.SetItemText(i, 4, szTemp);
			pBegin = (void*)((int)pBegin + 4);
		}
	}

	int a = nFaToRva(0x5face);
	wsprintf(szTemp, "%08X", a);
	a = nFaToVa(0x5face);
	wsprintf(szTemp, "%08X", a);
}

void CTwoDlg::ShowPESign()
{
	char szTemp[100] = {};
	CString cTemp;
	//清空列表
	m_lDataList.DeleteAllItems();
	while (m_lDataList.DeleteColumn(0));

	//2.添加新标题
	m_lDataList.InsertColumn(0, _T("Value"), LVCFMT_LEFT, m_rect.right / 5);
	m_lDataList.InsertColumn(0, _T("Size"), LVCFMT_LEFT, m_rect.right / 5);
	m_lDataList.InsertColumn(0, _T("Offset"), LVCFMT_LEFT, m_rect.right / 5);
	m_lDataList.InsertColumn(0, _T("Addr"), LVCFMT_LEFT, m_rect.right / 5);
	m_lDataList.InsertColumn(0, _T("Mem"), LVCFMT_LEFT, m_rect.right / 5);

	//添加成员
	m_lDataList.InsertItem(0, "Signature");
	//添加地址
	cTemp.Format(_T("0x%p"), m_pNT);
	m_lDataList.SetItemText(0, 1, cTemp);
	//添加偏移
	wsprintf(szTemp, "0X%p", m_nOffsetNT);
	m_lDataList.SetItemText(0, 2, szTemp);
	//添加大小
	m_lDataList.SetItemText(0, 3, "DWORD");
	//添加值
	wsprintf(szTemp, "%08X", *(DWORD*)m_pNT);
	m_lDataList.SetItemText(0, 4, szTemp);

}

void CTwoDlg::ShowFileHeader()
{
	char szTemp[100] = {};
	CString cTemp;
	//清空列表
	m_lDataList.DeleteAllItems();
	while (m_lDataList.DeleteColumn(0));

	//2.添加新标题
	m_lDataList.InsertColumn(0, _T("Value"), LVCFMT_LEFT, m_rect.right / 5);
	m_lDataList.InsertColumn(0, _T("Size"), LVCFMT_LEFT, m_rect.right / 5);
	m_lDataList.InsertColumn(0, _T("Offset"), LVCFMT_LEFT, m_rect.right / 5);
	m_lDataList.InsertColumn(0, _T("Addr"), LVCFMT_LEFT, m_rect.right / 5);
	m_lDataList.InsertColumn(0, _T("Mem"), LVCFMT_LEFT, m_rect.right / 5);

	int nOffset = m_nOffsetFile;
	void* pFile = (void*)m_pFILE;
	for (int i = 0; i < 7; i++) {
		ZeroMemory(szTemp, 100);
		//插入成员
		m_lDataList.InsertItem(i, s_FileHeaderMess[i].pInfo);
		//插入地址
		cTemp.Format(_T("0x%p"), pFile);
		m_lDataList.SetItemText(i, 1, cTemp);
		//插入偏移
		cTemp.Format(_T("0x%p"), nOffset);
		m_lDataList.SetItemText(i, 2, cTemp);
		if (i >= 2 && i <= 4)
		{
			//插入大小
			m_lDataList.SetItemText(i, 3, "DWORD");

			//插入值
			wsprintf(szTemp, "%08X", *(DWORD*)pFile);
			m_lDataList.SetItemText(i, 4, szTemp);

			pFile = (void*)((int)pFile + 4);
			nOffset = nOffset + 4;
		}
		else
		{
			//插入大小
			m_lDataList.SetItemText(i, 3, "WORD");

			//插入值
			wsprintf(szTemp, "%04X", *(WORD*)pFile);
			m_lDataList.SetItemText(i, 4, szTemp);

			pFile = (void*)((int)pFile + 2);
			nOffset = nOffset + 2;
		}
	}

}

void CTwoDlg::ShowOptionalHeader() 
{
	char szTemp[100] = {};
	CString cTemp;
	//清空列表
	m_lDataList.DeleteAllItems();
	while (m_lDataList.DeleteColumn(0));

	//2.添加新标题
	m_lDataList.InsertColumn(0, _T("Value"), LVCFMT_LEFT, m_rect.right / 5);
	m_lDataList.InsertColumn(0, _T("Size"), LVCFMT_LEFT, m_rect.right / 5);
	m_lDataList.InsertColumn(0, _T("Offset"), LVCFMT_LEFT, m_rect.right / 5);
	m_lDataList.InsertColumn(0, _T("Addr"), LVCFMT_LEFT, m_rect.right / 5);
	m_lDataList.InsertColumn(0, _T("Mem"), LVCFMT_LEFT, m_rect.right / 5);

	int nBegin = m_nOffsetOptional;
	void* pBegin = (void*)m_pOptional;
	for (int i = 0; i < 30 + m_pOptional->NumberOfRvaAndSizes; i++) {
		//插入成员
		m_lDataList.InsertItem(i, s_OptHeaderMess[i].pInfo);
		//插入地址
		cTemp.Format(_T("0x%p"), pBegin);
		m_lDataList.SetItemText(i, 1, cTemp);
		//插入偏移
		cTemp.Format(_T("0x%p"), nBegin);
		m_lDataList.SetItemText(i, 2, cTemp);

		//添加大小,值
		if (s_OptHeaderMess[i].nSize == 1)
		{
			//添加大小
			m_lDataList.SetItemText(i, 3, "BYTE");

			//添加值
			wsprintf(szTemp, "%02X", *(BYTE*)pBegin);
			m_lDataList.SetItemText(i, 4, szTemp);
			pBegin = (void*)((int)pBegin + 1);
		}
		else if (s_OptHeaderMess[i].nSize == 2)
		{
			m_lDataList.SetItemText(i, 3, "WORD");

			wsprintf(szTemp, "%04X", *(WORD*)pBegin);
			m_lDataList.SetItemText(i, 4, szTemp);
			pBegin = (void*)((int)pBegin + 2);
		}
		else if (s_OptHeaderMess[i].nSize == 4)
		{
			m_lDataList.SetItemText(i, 3, "DWORD");

			wsprintf(szTemp, "%08X", *(DWORD*)pBegin);
			m_lDataList.SetItemText(i, 4, szTemp);
			pBegin = (void*)((int)pBegin + 4);
		}
		else
		{
			m_lDataList.SetItemText(i, 3, "IMAGE_DATA_DIRECTORY");
			wsprintf(szTemp, "%08X %08X", *(DWORD*)pBegin, *(DWORD*)((int)pBegin + 4));
			m_lDataList.SetItemText(i, 4, szTemp);
			pBegin = (void*)((int)pBegin + 8);
		}
		nBegin += s_OptHeaderMess[i].nSize;
	}

}

void CTwoDlg::ShowSectionTable()
{
	//获取数量(单个40字节)
	int nNumber = m_pFILE->NumberOfSections;
	if (nNumber == 0) {
		AfxMessageBox("节表为空");
		return;
	}
	char szTemp[100] = {};
	ZeroMemory(szTemp, 100);
	//1.清空列表
	// 清空列表项
	m_lDataList.DeleteAllItems();
	// 清空列标题
	while (m_lDataList.DeleteColumn(0));

	//添加新标题
	m_lDataList.InsertColumn(0, _T("Value"), LVCFMT_LEFT, m_rect.right / 6);
	m_lDataList.InsertColumn(0, _T("Size"), LVCFMT_LEFT, m_rect.right / 6);
	m_lDataList.InsertColumn(0, _T("Addr"), LVCFMT_LEFT, m_rect.right / 6);
	m_lDataList.InsertColumn(0, _T("Offset"), LVCFMT_LEFT, m_rect.right / 6);
	m_lDataList.InsertColumn(0, _T("Mem"), LVCFMT_LEFT, m_rect.right / 6);
	m_lDataList.InsertColumn(0, _T("Name"), LVCFMT_LEFT, m_rect.right / 6);

	CString addressStr;
	int nBegin = m_nOffsetSection;
	void* pAddr = (void*)m_pSection;
	for (int i = 0; i < nNumber; i++) {
		//1.添加标题
		m_lDataList.InsertItem(i * 10, (char*)m_pSection[i].Name);
		//2.添加内部的信息
		for (int j = 0; j < 10; j++) {
			if (j != 0) {
				m_lDataList.InsertItem(i * 10 + j, "");
			}
			//1.添加Mem
			m_lDataList.SetItemText(i * 10 + j, 1, s_SecTableMess[j].pInfo);
			//添加Offset
			addressStr.Format(_T("% p"), nBegin);
			m_lDataList.SetItemText(i * 10 + j, 2, addressStr);
			nBegin += s_SecTableMess[j].nSize;
			//2.添加Addr
			addressStr.Format(_T("% p"), (pAddr));
			m_lDataList.SetItemText(i * 10 + j, 3, addressStr);
			//3.添加Size	
			//4.添加Value
			if (s_SecTableMess[j].nSize == 2) {
				m_lDataList.SetItemText(i * 10 + j, 4, "WORD");
				wsprintf(szTemp, "%04X", *(WORD*)pAddr);
				m_lDataList.SetItemText(i * 10 + j, 5, szTemp);
				pAddr = (void*)((int)pAddr + 2);
			}
			else if (s_SecTableMess[j].nSize == 4) {
				m_lDataList.SetItemText(i * 10 + j, 4, "DWORD");
				wsprintf(szTemp, "%04X", *(DWORD*)pAddr);
				m_lDataList.SetItemText(i * 10 + j, 5, szTemp);
				pAddr = (void*)((int)pAddr + 4);
			}
			else {
				m_lDataList.SetItemText(i * 10 + j, 4, "BYTE*8");
				wsprintf(szTemp, "%02X%02X%02X%02X%02X%02X%02X%02X",
					*(BYTE*)pAddr,
					*(BYTE*)((int)pAddr + 1),
					*(BYTE*)((int)pAddr + 2),
					*(BYTE*)((int)pAddr + 3),
					*(BYTE*)((int)pAddr + 4),
					*(BYTE*)((int)pAddr + 5),
					*(BYTE*)((int)pAddr + 6),
					*(BYTE*)((int)pAddr + 7));
				m_lDataList.SetItemText(i * 10 + j, 5, szTemp);
				pAddr = (void*)((int)pAddr + 8);
			}
		}
	}
}

void CTwoDlg::ShowImport()
{
	if (m_nOffsetImport == 0)
	{
		AfxMessageBox("无导入表");
		return;
	}
	char szTemp[100] = {};
	CString cTemp;
	//清空列表
	m_lDataList.DeleteAllItems();
	while (m_lDataList.DeleteColumn(0));

	//2.添加新标题
	m_lDataList.InsertColumn(0, _T("Addr"), LVCFMT_LEFT, m_rect.right / 3);
	m_lDataList.InsertColumn(0, _T("Func"), LVCFMT_LEFT, m_rect.right / 3);
	m_lDataList.InsertColumn(0, _T("Dll"), LVCFMT_LEFT, m_rect.right / 3);
	IMAGE_IMPORT_DESCRIPTOR impEnd = { 0 };
	IMAGE_IMPORT_DESCRIPTOR* m_pTemp = m_pImport;
	int nNum = 0;//记录当前所在行
	int nRow = 0;
	while (true)
	{
		//插入DLL名
		char* pDllName = (char*)(nRvaToFa(m_pTemp[nNum].Name) + (int)m_pView);
		m_lDataList.InsertItem(nRow, pDllName);


		//获取导入地址表
		LPDWORD pINT = (LPDWORD)(nRvaToFa(m_pTemp[nNum].FirstThunk) + (int)m_pView);
		if (m_pTemp->OriginalFirstThunk != 0)
		{
			pINT = (LPDWORD)(nRvaToFa(m_pTemp[nNum].OriginalFirstThunk) + (int)m_pView);
		}
		//遍历导入地址表，获取导入函数地址，填入IAT
		BOOL bIsFirst = TRUE;
		while (*pINT != 0) {
			if (bIsFirst) {
				bIsFirst = FALSE;
			}
			else {
				m_lDataList.InsertItem(nRow, "");
			}
			cTemp.Format(_T("0x%p"), pINT);
			m_lDataList.SetItemText(nRow, 2, cTemp);
			m_lDataList.SetItemText(nRow, 1, ((PIMAGE_IMPORT_BY_NAME)(nRvaToFa (*pINT) + (int)m_pView))->Name);
			nRow++;
			pINT++;
		}


		if (memcmp((const void*)&m_pTemp[nNum + 1], (const void*)&impEnd, sizeof(impEnd)) == 0)
		{
			break;
		}
		nNum++;
	}
}

void CTwoDlg::ShowExport()
{
	if (m_nOffsetExport == 0)
	{
		AfxMessageBox("无导出表");
		return;
	}
	char szTemp[100] = {};
	CString cTemp;
	BOOL bFlag = FALSE;
	//清空列表
	m_lDataList.DeleteAllItems();
	while (m_lDataList.DeleteColumn(0));

	//2.添加新标题
	m_lDataList.InsertColumn(0, _T("Addr"), LVCFMT_LEFT, m_rect.right / 3);
	m_lDataList.InsertColumn(0, _T("Name"), LVCFMT_LEFT, m_rect.right / 3);
	m_lDataList.InsertColumn(0, _T("Seq"), LVCFMT_LEFT, m_rect.right /  3);

	DWORD* pAddrOfFunc = (DWORD*)(nRvaToFa(m_dwAddrOfFunction) + (int)m_pView);
	WORD* pAddrOfOrdinal = (WORD*)(nRvaToFa(m_dwAddrOfOrdinal) + (int)m_pView);
	DWORD* pAddrOfNames = (DWORD*)(nRvaToFa(m_dwAddrOfNames) + (int)m_pView);

	int nIndex = 0;
	for (int i = 0; i < m_dwNumOfFunctions; i++){
		//空
		if (!pAddrOfFunc) {
			AfxMessageBox("导出表读取失败");
			return;
		}
		if (pAddrOfFunc[i] == 0){
			continue;
		}
		bFlag = FALSE;
		//插入序号
		cTemp.Format(_T("%08X"), (DWORD)(nIndex + m_dwBase));
		m_lDataList.InsertItem(nIndex, cTemp);
		//插入名字（遍历名称表）
		for (int j = 0; j < m_dwNumOfNames; j++)
		{
			if (pAddrOfOrdinal[j] == i)
			{
				bFlag = true;
				//插入函数名
				m_lDataList.SetItemText(nIndex, 1, (LPCTSTR)(nRvaToFa(pAddrOfNames[j]) + (int)m_pView));
				break;
			}
		}
		if (!bFlag)
		{
			m_lDataList.SetItemText(nIndex, 1, "N/A");
		}
		//插入地址
		cTemp.Format(_T("%08X"), nRvaToFa(pAddrOfFunc[i]));
		m_lDataList.SetItemText(nIndex, 2, cTemp);
		nIndex++;
	}

}

void CTwoDlg::ShowRelocation()
{
	if (m_nOffsetExport < 5)
	{
		AfxMessageBox("无重定位表");
		return;
	}
	char szTemp[100] = {};


	CString cTemp;
	int nSize = 0;
	int nCount = 0;
	//清空列表
	m_lDataList.DeleteAllItems();
	while (m_lDataList.DeleteColumn(0));

	//2.添加新标题
	m_lDataList.InsertColumn(0, _T("Offset"), LVCFMT_LEFT, m_rect.right / 3);
	m_lDataList.InsertColumn(1, _T("Page"), LVCFMT_LEFT, m_rect.right / 3);
	m_lDataList.InsertColumn(2, _T("Addr"), LVCFMT_LEFT, m_rect.right / 3);

	int nTraced = 0; //已经遍历的大小，和m_nSizeOfRelocation 构成边界
	int nNowOffset = m_nOffsetRelocation;//当前偏移
	IMAGE_BASE_RELOCATION* mNow = m_pRelocation; //当前重定位表
	int nRow = 0;						//当前行
	WORD* pCurrentOffset = 0;//地址循环
	//分页循环
	while (nTraced < m_nSizeOfRelocation) {
		nSize = mNow->SizeOfBlock;			 //当前分页重定位表的大小
		nCount = (nSize - 8) / 2;			 //当前分页重定位表的个数
		nNowOffset = nNowOffset + 8;		 //指向柔性数组
		pCurrentOffset = (WORD*)((int)mNow + sizeof(IMAGE_BASE_RELOCATION));//获取分页中的地址
		//地址循环
		for (int i = 0; i < nCount;i++) {
			////插入偏移
			//cTemp.Format(_T("0X%08X", nNowOffset));
			//m_lDataList.InsertItem(nRow,cTemp);
			////插入分页
			//cTemp.Format(_T("0X%08X", mNow->VirtualAddress));
			//m_lDataList.SetItemText(nRow,1, cTemp);
			////插入地址(消掉第一个)
			//cTemp.Format(_T("0X%08X", ((pCurrentOffset[i]>>12) & 0Xf))); //有差异
			//m_lDataList.SetItemText(nRow, 2, cTemp);

			//插入偏移
			wsprintf(szTemp, "0X%08X", nNowOffset);
			m_lDataList.InsertItem(nRow, szTemp);
			//插入分页
			wsprintf(szTemp, "0X%08X", mNow->VirtualAddress);
			m_lDataList.SetItemText(nRow, 1, szTemp);
			//插入地址(消掉第一个)
			wsprintf(szTemp, "0X%08X", (pCurrentOffset[i] & 0Xfff));
			m_lDataList.SetItemText(nRow, 2, szTemp);


			nNowOffset += 2;
			nRow++;
		}
		nTraced += nSize;								   //完成当前分页
		mNow = (IMAGE_BASE_RELOCATION*)((int)mNow + nSize);//指向下一个分页
	}
}


//重写回车键
void CTwoDlg::OnOK()
{
}


