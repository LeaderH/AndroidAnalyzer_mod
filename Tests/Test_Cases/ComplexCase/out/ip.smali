.class public Lip;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/content/DialogInterface$OnClickListener;


# instance fields
.field final synthetic a:Lcom/tndev/funnyframes/MenuActivity;


# direct methods
.method public constructor <init>(Lcom/tndev/funnyframes/MenuActivity;)V
    .registers 2
    .parameter

    .prologue
    .line 1
    iput-object p1, p0, Lip;->a:Lcom/tndev/funnyframes/MenuActivity;

    .line 194
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onClick(Landroid/content/DialogInterface;I)V
    .registers 4
    .parameter
    .parameter

    .prologue
    .line 197
    iget-object v0, p0, Lip;->a:Lcom/tndev/funnyframes/MenuActivity;

    invoke-virtual {v0}, Lcom/tndev/funnyframes/MenuActivity;->finish()V

    .line 198
    return-void
.end method
