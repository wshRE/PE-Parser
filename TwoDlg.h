
// TwoDlg.h: 头文件
//

#pragma once


// CTwoDlg 对话框
class CTwoDlg : public CDialogEx
{
// 构造
public:
	CTwoDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_TWO_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnSelchangedTree(NMHDR* pNMHDR, LRESULT* pResult);				//树选择
	afx_msg void OnBnClickedWritein();											//点击写入程序
	virtual void OnOK();														//重写回车
	BOOL GetFileMess();															//获取打开的文件信息
	BOOL TreeFileInit();														//树初始化
	//地址转换
	int nVaToRva(int nVa);
	int nVaToFa(int nVa);
	int nRvaTova(int nRva);
	int nRvaToFa(int nRva);
	int nFaToRva(int nFa);
	int nFaToVa(int nFa);
	//获取所在节的文件偏移
	int getFileOffsetFromAddress(int address);
	//获取所在节的内存偏移
	int getMemoryOffsetFromAddress(int address);
	void ShowDosHeader();      //显示DOS头
	void ShowPESign();         //PE标识
	void ShowFileHeader();     //显示PE头
	void ShowOptionalHeader(); //显示可选PE头
	void ShowSectionTable();   //显示节表
	void ShowImport();         //显示导入表
	void ShowExport();         //显出导出表
	void ShowRelocation();     //重定位表
public:
	CTreeCtrl m_tTreeFile;								//树
	CListCtrl m_lDataList;								//列表
	HANDLE m_hFile = 0;									//文件句柄
	HANDLE m_hFileMap = 0;								//文件映射
	LPVOID m_pView = 0;									//文件映射视图
	char m_szPath[MAX_PATH] = {0};						//文件路径	
	char m_szProcessName[MAX_PATH] = { 0 };				//进程名
	RECT  m_rect;										//list大小
	//----PE结构-----
	_IMAGE_DOS_HEADER* m_pDOS = nullptr;				//DOS头
	_IMAGE_NT_HEADERS* m_pNT = nullptr;					//NT头
	IMAGE_FILE_HEADER* m_pFILE = nullptr;				//文件头
	IMAGE_OPTIONAL_HEADER32* m_pOptional = nullptr;		//选项头
	IMAGE_SECTION_HEADER* m_pSection = nullptr;			//节表
	IMAGE_IMPORT_DESCRIPTOR* m_pImport = nullptr;		//导入表
	IMAGE_EXPORT_DIRECTORY* m_pExport = nullptr;		//导出表 
	IMAGE_BASE_RELOCATION* m_pRelocation = nullptr;		//重定位表
		//----偏移计算----
	int m_nOffsetDos = 0;								
	int m_nOffsetNT = 0;								
	int m_nOffsetFile = 0;								
	int m_nOffsetOptional = 0;							
	int m_nOffsetSection = 0;							
	int m_nOffsetFirstSection = 0;		
	int m_nOffsetImport = 0;
	int m_nOffsetExport = 0;
		//----其他----
	int m_nImageBase = 0;								//内存镜像基址
	int m_nSectionTableNum = 0;							//节表个数
	DWORD m_FileSize = 0;								// 文件大小(CreateFileMap获取,没写
	DWORD m_nFileAlignment = 0;							//文件对齐大小
	DWORD m_nSectionAlignment = 0;						//内存对齐大小
	DWORD m_dwNumOfFunctions = 0;						//导出函数总个数
	DWORD m_dwNumOfNames = 0;							//导出函数名个数
	DWORD m_dwAddrOfFunction = 0;						//导出函数地址表RVA
	DWORD m_dwAddrOfNames = 0;							//导出函数名称表RVA
	DWORD m_dwAddrOfOrdinal = 0;						//导出函数序号表RVA
	DWORD m_dwBase = 0;									//导出函数起始序号
	int m_nNumberOfData = 0;							//数据目录个数
	int m_nOffsetRelocation = 0;						//重定位表偏移
	int m_nSizeOfRelocation = 0;						//重定位表数量
	//---------操作-------
	int m_nCurrentSelect = OP_NONE; //当前操作
	enum
	{
		OP_NONE,
		OP_DOS,
		OP_NT,
		OP_FILE,
		OP_OPTIONAL,
		OP_SECTION,
		OP_ADDRCHANGE,
		OP_IMPORTDLL,     //导入表DLL部分
		OP_IMPORTFUNC,    //导入表FUNC部分
		OP_EXPORTDLL,     //导出表
	};
};
//---------PE结构
struct DOS_HEADER_STRUCT
{
	int nSize;
	char* pInfo;
};

struct FILE_HEADER_STRUCT
{
	int nSize;
	char* pInfo;
};


struct MACHINE
{
	WORD wData;
	char* pInfo;
};


struct CHARACTERISTICS
{
	WORD wData;
	char* pInfo;
};

struct PE_OPTION_HEADER_STRUCT
{
	int nSize;
	char* pInfo;
};


struct SECTION_TABLE
{
	int nSize;
	char* pInfo;
};

struct EXPORT_TABLE
{
	int nSize;
	char* pInfo;
	char* pDescription;
};