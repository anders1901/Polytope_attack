#include <setjmp.h>

#if defined HAVE_CONFIG_H
# include "config.h"
#endif

#define driverVERSION "5.5.0.10"

#define CheckInterrupted(lpsolvecaller, interrupted)

#if defined MATLAB
# include "matlab.h"
#elif defined OMATRIX
# include "omatrix.h"
#elif defined SCILAB
# include "scilab.h"
#elif defined OCTAVE
# include "octave.h"
#elif defined PYTHON
# include "pythonmod.h"
#elif defined PHP
# include "PHPmod.h"
#elif defined FREEMAT
# include "freemat.h"
#elif defined SYSQUAKE
# include "Sysquake.h"
#elif defined EULER
# include "euler.h"
#else
# error "Unknown platform. Either MATLAB, OMATRIX, SCILAB, OCTAVE, PYTHON, PHP, FREEMAT, SYSQUAKE, EULER must be defined."
#endif

#define cmdsz     50

struct structallocatedmemory
{
  void *ptr;
  struct structallocatedmemory *next;
};

typedef struct
{
  lprec         *lp;
  int           h;
  char          cmd[cmdsz];
  void          *newbranch;
  void          *newbranchhandle;
  void          *newnode;
  void          *newnodehandle;
  void          *newabort;
  void          *newaborthandle;
  void          *newlog;
  void          *newloghandle;
  void          *newmsg;
  void          *newmsghandle;
  structlpsolvecaller lpsolvecaller;
  struct structallocatedmemory *allocatedmemory;
} structlpsolve;

extern void exitnow(structlpsolvecaller *lpsolvecaller);

#if !defined ErrMsgTxt
extern int ErrMsgTxt(structlpsolvecaller *lpsolvecaller, char *str);
#endif
#if !defined GetpMatrix
extern rMatrix GetpMatrix(structlpsolvecaller *lpsolvecaller, int element);
#endif
extern int GetString(structlpsolvecaller *lpsolvecaller, pMatrix ppm, int element, char *buf, int size, int ShowError);
extern Double GetRealScalar(structlpsolvecaller *lpsolvecaller, int element);
#if !defined GetM
extern int GetM(structlpsolvecaller *lpsolvecaller, rMatrix arg);
#endif
#if !defined GetN
extern int GetN(structlpsolvecaller *lpsolvecaller, rMatrix arg);
#endif
extern int GetIntVector(structlpsolvecaller *lpsolvecaller, int element, int *vec, int start, int len, int exactcount);
extern int GetRealVector(structlpsolvecaller *lpsolvecaller, int element, Double *vec, int start, int len, int exactcount);
extern int GetRealSparseVector(structlpsolvecaller *lpsolvecaller, int element, Double *vec, int *index, int start, int len, int col);
extern strArray GetCellCharItems(structlpsolvecaller *lpsolvecaller, int element, int len, int ShowError);
#if !defined GetCellString
extern void GetCellString(structlpsolvecaller *lpsolvecaller, strArray pa, int element, char *buf, int len);
#endif
extern void *GetVariant(structlpsolvecaller *lpsolvecaller, int element);
extern void FreeVariant(PyObject *var);

extern void *GetFunction(structlpsolvecaller *lpsolvecaller, int element);
#if !defined FreeFunction
extern void FreeFunction(PyObject *function);
#endif

extern void FreeCellCharItems(strArray pa, int len);
extern double *CreateDoubleMatrix(structlpsolvecaller *lpsolvecaller, int m, int n, int element);
#if !defined CreateDoubleSparseMatrix
extern double *CreateDoubleSparseMatrix(structlpsolvecaller *lpsolvecaller, int m, int n, int element);
#endif
#if !defined SetDoubleMatrix
extern void SetDoubleMatrix(structlpsolvecaller *lpsolvecaller, double *mat, int m, int n, int element, int freemat);
#endif
#if !defined CreateLongMatrix
extern Long *CreateLongMatrix(structlpsolvecaller *lpsolvecaller, int m, int n, int element);
#endif
#if !defined SetLongMatrix
extern void SetLongMatrix(structlpsolvecaller *lpsolvecaller, long *mat, int m, int n, int element, int freemat);
#endif
extern void SetColumnDoubleSparseMatrix(structlpsolvecaller *lpsolvecaller, int element, int m, int n, double *mat, int column, double *arry, int *index, int size, int *nz);
extern void CreateString(structlpsolvecaller *lpsolvecaller, char **str, int m, int element);
#if !defined CheckInterrupted
extern void CheckInterrupted(structlpsolvecaller *lpsolvecaller, short *interrupted);
#endif
#if !defined branchfunction
extern int __WINAPI branchfunction(lprec *lp, void *branchhandle, int column);
#endif
#if !defined nodefunction
extern int __WINAPI nodefunction(lprec *lp, void *nodehandle, int vartype);
#endif
#if !defined abortfunction
extern int __WINAPI abortfunction(lprec *lp, void *userhandle);
#endif
#if !defined logfunction
extern void __WINAPI logfunction(lprec *lp, void *userhandle, char *buf);
#endif
#if !defined msgfunction
extern void __WINAPI msgfunction(lprec *lp, void *userhandle, int msg);
#endif

#ifdef FORTIFY
# include "lp_fortify.h"
#endif
